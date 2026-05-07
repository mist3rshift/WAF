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


void showCerts_client(SSL* ssl){
    X509 *cert;
    char *subject, *issuer;
    
    cert = SSL_get_peer_certificate(ssl); // get the server's certificate
    if(cert != NULL){
        subject = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0); // get certificat's subject
        issuer = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0); // get certificat's issuer
        
        printf("[+] Server certificates :\n");
        printf("\tSubject: %s\n", subject);
        printf("\tIssuer: %s\n", issuer);
        
        free(subject); // free the malloc'ed string
        free(issuer); // free the malloc'ed string
        X509_free(cert); // free the malloc'ed certificate copy
        if(SSL_get_verify_result(ssl) == X509_V_OK) // check certificat's trust
        printf("[+] Server certificates X509 is trust!\n");
        else
        printf("[-] Server certificates X509 is not trust...\n");
    }
    else
    printf("[-] No server's certificates\n");
    return;
}

void handle_client(int client_sock, SSL *ssl){
    char buffer[BUFFER_SIZE];

    SSL_set_fd(ssl, client_sock); // attach the socket descriptor

    if(SSL_accept(ssl) == -1) // make the SSL connection
    ERR_print_errors_fp(stderr);
    else{
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY); }

    // 3. Connexion to web server  (Upstream)
    int web_server_sock = initialize_server_web_connection();
    if (web_server_sock < 0) {
        const char *response = "HTTP/1.1 503 OK\r\nContent-Length: 23\r\n\r\nWeb Server unreachable \n";
        SSL_write(ssl, response, strlen(response));
        close(client_sock);
        return;
    }

    //Loop if message to long 
    int bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_read <= 0) {
        log_error("handle_client : no bytes received \n");
        close(client_sock);
        return;
    }

    buffer[bytes_read] = '\0';

    String src;
    src.ptr = buffer;
    src.len = bytes_read;

    Request req;

    parse_request(src, &req);

    WafEvent event;

    get_timestamp(event.timestamp);;
    event.request_id = get_unique_id();
    event.threshold = 5;

    if(perform_waf_analysis(&req, &event)) {
        const char *response = "HTTP/1.1 403 OK\r\nContent-Length: 23\r\n\r\nAccess denied \n";
        SSL_write(ssl, response, strlen(response));
        close(client_sock);
        log_event_json(&event);
        free(event.request_id);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return;
    }
    
    SSL_get_cipher(ssl);
    showCerts_client(ssl);

    //send to web server 
    SSL_write(ssl,buffer,sizeof(buffer)-1);
    
    //relay web server response to  client
    relay_stream(web_server_sock,client_sock);

    client_sock = SSL_get_fd(ssl); // get traditionnal socket connection from SSL connection
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_sock);
    close(web_server_sock);
    log_event_json(&event);
    free(event.request_id);
}

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
    int web_server_sock = -1; // I,itialize to -1 to indicate no connection yet

    SSL_set_fd(ssl, client_sock); // attach the socket descriptor

    if(SSL_accept(ssl) == -1) // make the SSL connection
    ERR_print_errors_fp(stderr);
    else{
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY); }

    // 3. Connexion to web server (Upstream)
    web_server_sock = initialize_server_web_connection();
    if (web_server_sock < 0) {
        
        const char *response = "HTTP/1.1 503 OK\r\nContent-Length: 23\r\n\r\nWeb Server unreachable \n";
        SSL_write(ssl, response, strlen(response));
        cleanup_client_session(client_sock, web_server_sock, client_args);
        log_error("handle_client_thread : failed to connect to web server for thread %lu\n", thread_id);
        pthread_exit(NULL);
    }
 
    //Loop if message to long
    int bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_read <= 0) {
        log_error("handle_client : no bytes received \n");
        cleanup_client_session(client_sock, web_server_sock, client_args);
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
    event.threshold = 5;

    if(perform_waf_analysis(&req, &event)) {
        const char *response = "HTTP/1.1 403 OK\r\nContent-Length: 23\r\n\r\nAccess denied \n";
        SSL_write(ssl, response, strlen(response));
        close(client_sock);
        log_event_json(&event);
        free(event.request_id);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        pthread_exit(NULL);
    }
    
    SSL_get_cipher(ssl);
    showCerts_client(ssl);

    //send to web server 
    SSL_write(ssl,buffer,sizeof(buffer)-1);
    
    //relay web server response to  client
    relay_stream(web_server_sock,client_sock);

    
    log_debug("handle_client_thread : closing connection for thread %lu\n", thread_id);
    cleanup_client_session(client_sock, web_server_sock, client_args);
    log_debug("handle_client_thread : thread %d exiting\n", thread_id);
    log_event_json(&event);
    free(event.request_id);
    SSL_shutdown(ssl);
    SSL_free(ssl);
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


