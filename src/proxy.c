#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <openssl/crypto.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include "../lib/log.h"
#include "../inc/proxy.h"
#include "../inc/config.h"
#include "../inc/client_handler.h"
#include "../inc/firewall.h"

int proxy_socket = -1; // global socket for signal handler access
SSL_CTX *ctx = NULL; // global

int initialise_proxy_socket(int port){
    //AF_INET: Specifies IPv4.
    int proxy_socket = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if (proxy_socket < 0) {
        log_error("create_server_socket :Socket creation failed");
        exit(EXIT_FAILURE);

    }
    if (setsockopt(proxy_socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
    log_error("create_server_socket : setsockopt(SO_REUSEADDR) failed");

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; // Bind to any IP
    //Converts the port to network byte order.
    address.sin_port = htons(port);       // Use the port parameter

    if (bind(proxy_socket, (struct sockaddr*)&address, sizeof(address)) < 0) {
        log_error("create_server_socket :Bind failed \n ");
        exit(EXIT_FAILURE);
    }
    
    
    if (listen(proxy_socket, MAX_CLIENT) < 0) {
    log_error("create_server_socket :Listen failed \n");
    exit(EXIT_FAILURE);
    }

    return proxy_socket;
}



SSL_CTX* initSSLContext(){
    const SSL_METHOD *method;

    method = TLS_server_method();
    
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(method); // create new context from selected method
    if(ctx == NULL){
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void loadCertificates(SSL_CTX* ctx, const char* certFile, const char* keyFile){
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    // Require certificate and key files to be provided; do not generate keys.
    if(certFile == NULL || keyFile == NULL){
        fprintf(stderr, "[-] Certificate or private key file not provided.\n");
        exit(EXIT_FAILURE);
    }

    printf("[*] Loading server's certificate and private key from files...\n");
    if (SSL_CTX_use_certificate_file(ctx, certFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    printf("[*] Server's certificate and private key loaded from file.\n");
    
    // Verify private key matches the public key in the certificate
    if(!SSL_CTX_check_private_key(ctx)){
        fprintf(stderr, "[-] Private key does not match the public certificate...\n");
        abort();
    } else {
        printf("[+] Server's private key match public certificate!\n");
    }
    // Do not request or verify client certificates (no mutual TLS)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    
    return;
}

void start_proxy(int port) {
    const char *certFile, *keyFile;
    
    ctx = initSSLContext();
    loadCertificates(ctx, CERT_PATH, KEY_PATH);

    proxy_socket = initialise_proxy_socket(port);
    struct sockaddr_in client_addr;
    socklen_t addr_size = sizeof(client_addr);
    pthread_t thread;
    log_info("start_proxy : WAF listening on port %d...\n", port);
    SSL *ssl;

    while(1) {
        
        int client_sock = accept(proxy_socket, (struct sockaddr *)&client_addr, &addr_size);
        log_info("start_proxy : client socket %d accepted\n", client_sock);
        if (client_sock < 0) {
            log_error("start_proxy :Accept failed");
            continue; // waiting for customer
        }
        // puis dans la boucle :
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sock);

        // OPTION A : Direct connection (Single-thread for the MVP)
        //handle_client(client_sock); 
        
        // OPTION B : Use threads to handle multiple clients concurrently
        ClientArgs *client_args = calloc(1, sizeof(ClientArgs));
        client_args->client_fd = client_sock;
        client_args->client_addr = client_addr;
        client_args->thread_id = 0; // will be set in the thread function
        client_args->ssl = ssl;
        pthread_create(&thread,0, handle_client_thread, (void*)client_args);
    }
}

int relay_stream(int socket_recv, int socket_to_write) {
    char buffer[BUFFER_SIZE];
    int bytes_read;

    //loop to relay data from web server to client until the connection is closed
    while ((bytes_read = recv(socket_recv, buffer, sizeof(buffer), 0)) > 0) {
        log_debug("relay_stream : received %d bytes\n : message : %s", bytes_read,buffer);
        // Relay the data to the client
        if (send(socket_to_write, buffer, bytes_read, 0) < 0) {
            log_error("relay_stream : error sending data to client");
            break;
        }
    }

    if (bytes_read < 0) {
        log_error("relay_stream : error during recv from web server");
    }
    return 0;
}

void stop_waf_handler(int signum) {
    log_info("\nStopping WAF (Signal %d)...", signum);
    
    if (proxy_socket >= 0) {
        SSL_CTX_free(ctx); 
        close(proxy_socket);
        log_info("Main proxy socket closed.");
    }

    // Mutex cleanup if needed
    // pthread_mutex_destroy(&log_mutex);

    log_info("WAF stopped properly. Goodbye!");
    free_rules();
    exit(0);
}