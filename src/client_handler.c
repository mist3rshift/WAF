#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../inc/config.h"
#include "../inc/client_handler.h"
#include "../lib/log.h"
#include "../inc/backend_connection.h"
#include "../inc/proxy.h"
#include "../inc/firewall.h"
#include "../inc/request_parser.h"
#include "../inc/internal_log.h"


void* handle_client_thread(void *args) {
    pthread_detach(pthread_self()); // Detach the thread to allow for automatic resource cleanup
    //Extract client information from args
    ClientArgs *client_args = (ClientArgs *)args;
    int client_sock = client_args->client_fd;
    struct sockaddr_in client_addr = client_args->client_addr;
    SSL *ssl = client_args->ssl;
    pthread_t thisThread = pthread_self();
    unsigned long thread_id = (unsigned long) thisThread; // Use thread ID for logging
    
    log_info("handle_client_thread : thread %lu handling client socket %d\n", thread_id, client_sock);

    char buffer[BUFFER_SIZE]; 
    int web_server_sock = -1; // Initialize to -1 to indicate no connection yet
    int bytes_read = 0;
    int use_ssl = 1; // Assume SSL by default

    // Peek at the first byte to detect protocol (SSL vs plain HTTP)
    unsigned char first_byte;
    int peek_result = recv(client_sock, &first_byte, 1, MSG_PEEK);
    
    if (peek_result > 0) {
        // Check if this is a TLS Client Hello (0x16 = Handshake) or HTTP request
        // HTTP requests start with: G(0x47), P(0x50), D(0x44), H(0x48), T(0x54), O(0x4F), C(0x43), etc.
        if (first_byte == 0x16 || first_byte == 0x14 || first_byte == 0x15 || first_byte == 0x17) {
            // TLS/SSL record type (Handshake, Change Cipher, Alert, Application Data)
            use_ssl = 1;
        } else if ((first_byte >= 0x41 && first_byte <= 0x5A) || (first_byte >= 0x61 && first_byte <= 0x7A)) {
            // ASCII letter: likely HTTP (GET, POST, HEAD, PUT, DELETE, etc.)
            use_ssl = 0;
        } else {
            // Unknown protocol, try SSL anyway
            use_ssl = 1;
        }
    }

    // Handle SSL connection if needed
    if (use_ssl) {
        SSL_set_fd(ssl, client_sock); // attach the socket descriptor
        
        int ssl_ret = SSL_accept(ssl);
        if (ssl_ret <= 0) {
            int ssl_err = SSL_get_error(ssl, ssl_ret);
            log_error("handle_client_thread : SSL_accept failed with error %d for thread %lu\n", ssl_err, thread_id);
            ERR_print_errors_fp(stderr);
            cleanup_client_session(client_sock, web_server_sock, client_args);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            pthread_exit(NULL);
        }
        
        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
        
        // Read from SSL connection
        bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    } else {
        // Plain HTTP: read directly from socket
        bytes_read = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    }
    
    if (bytes_read <= 0) {
        log_error("handle_client_thread : no bytes received for thread %lu\n", thread_id);
        cleanup_client_session(client_sock, web_server_sock, client_args);
        if (use_ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        pthread_exit(NULL);
    }
    
    buffer[bytes_read] = '\0';

    String src;
    src.ptr = buffer;
    src.len = bytes_read;

    Request req;

    parse_request(src, &req);

    WafEvent event;

    get_timestamp(event.timestamp);
    event.request_id = get_unique_id();
    event.threshold = THRESHOLD;
    inet_ntop(AF_INET, &client_addr.sin_addr, event.client_ip, sizeof(event.client_ip));

    // 3. Connection to web server (Upstream)
    web_server_sock = initialize_server_web_connection();
    if (web_server_sock < 0) {
        const char *response = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 23\r\n\r\nWeb Server unreachable \n";
        if (use_ssl) {
            SSL_write(ssl, response, strlen(response));
        } else {
            send(client_sock, response, strlen(response), 0);
        }
        cleanup_client_session(client_sock, web_server_sock, client_args);
        log_error("handle_client_thread : failed to connect to web server for thread %lu\n", thread_id);
        if (use_ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        pthread_exit(NULL);
    }

    // WAF Analysis
    if(perform_waf_analysis(&req, &event)) {
        const char *response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 15\r\n\r\nAccess denied\n";
        if (use_ssl) {
            SSL_write(ssl, response, strlen(response));
        } else {
            send(client_sock, response, strlen(response), 0);
        }
        log_event_json(&event);
        free(event.request_id);
        cleanup_client_session(client_sock, web_server_sock, client_args);
        if (use_ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        pthread_exit(NULL);
    }
    


    // Forward request to web server
    if (send(web_server_sock, buffer, bytes_read, 0) < 0) {
        log_error("handle_client_thread : failed to send request to web server\n");
        cleanup_client_session(client_sock, web_server_sock, client_args);
        if (use_ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        pthread_exit(NULL);
    }
    
    // Relay web server response to client
    if (use_ssl) {
        char relay_buffer[BUFFER_SIZE];
        int relay_bytes;
        while ((relay_bytes = recv(web_server_sock, relay_buffer, sizeof(relay_buffer), 0)) > 0) {
            SSL_write(ssl, relay_buffer, relay_bytes);
        }
    } else {
        char relay_buffer[BUFFER_SIZE];
        int relay_bytes;
        while ((relay_bytes = recv(web_server_sock, relay_buffer, sizeof(relay_buffer), 0)) > 0) {
            send(client_sock, relay_buffer, relay_bytes, 0);
        }
    }

    event.bytes_sent = bytes_read;
    log_debug("handle_client_thread : closing connection for thread %lu\n", thread_id);
    log_event_json(&event);
    free(event.request_id);
    cleanup_client_session(client_sock, web_server_sock, client_args);
    

    
    pthread_exit(NULL);
}


void cleanup_client_session(int client_fd, int web_fd,ClientArgs *client_args) {
    if (client_fd >= 0) {
        close(client_fd);// release SSL's context
        log_debug("Client socket %d closed.", client_fd);
    }
    
    if (web_fd >= 0) {
        close(web_fd);
        log_debug("Web server socket %d closed.", web_fd);
    }

    if (client_args != NULL) {
        free(client_args);
        log_debug("Memory for client_args freed.");
    }
}


