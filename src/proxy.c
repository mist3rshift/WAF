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

void makekCert(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days){
    X509 *x;
    EVP_PKEY *pk;
    RSA *rsa;
    X509_NAME *name = NULL;
    
    // 1. Génération de la clé directement en EVP_PKEY
    *pkeyp = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)bits);
    if (!*pkeyp) return;

    // 2. Création du certificat X509
    *x509p = X509_new();
    X509_set_version(*x509p, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(*x509p), serial);
    X509_gmtime_adj(X509_get_notBefore(*x509p), 0);
    X509_gmtime_adj(X509_get_notAfter(*x509p), (long)60*60*24*days);
    
    // Associer la clé au certificat
    X509_set_pubkey(*x509p, *pkeyp); // define public key in cert
    name = X509_get_subject_name(x);
    
    // This function creates and adds the entry, working out the
    // correct string type and performing checks on its length.
    // Normally we'd check the return value for errors...
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"XX", -1, -1, 0); // useless if more anonymity needed
    X509_NAME_add_entry_by_txt(name,"CN", MBSTRING_ASC, (const unsigned char*)"ASRAT", -1, -1, 0); // useless if more anonymity needed
    
    // Its self signed so set the issuer name to be the same as the subject.
    X509_set_issuer_name(*x509p, name);
    
    if(!X509_sign(*x509p, *pkeyp, EVP_sha256())) // secured more with sha1? md5/sha1? sha256?
    abort();
    
    *x509p = x;
    *pkeyp = pk;
    return;
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

    if(certFile == NULL || keyFile == NULL){
    
    printf("[*] Generate random server's certificat and private key.\n");
    makekCert(&cert, &pkey, 2048, 0, 0);
    SSL_CTX_use_certificate(ctx, cert);
    SSL_CTX_use_PrivateKey(ctx, pkey);
    
    // set the local certificate from certFile if certFile specified
    // set the private key from keyFile (may be the same as certFile) if specified
    } else if (SSL_CTX_use_PrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
    } else
    printf("[*] Server's certificat and private key loaded from file.\n");
    
    // verify private key match the public key into the certificate
    if(!SSL_CTX_check_private_key(ctx)){
    fprintf(stderr, "[-] Private key does not match the public certificate...\n");
    abort();
    } else
    printf("[+] Server's private key match public certificat !\n");
    return;
}

void showCerts(SSL* ssl){
    X509 *cert;
    char *subject, *issuer;
    
    cert = SSL_get_peer_certificate(ssl); // get the client's certificate
    if(cert != NULL){
    subject = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0); // get certificate's subject
    issuer = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0); // get certificate's issuer
    
    printf("[+] Client certificates :\n");
    printf("\tSubject: %s\n", subject);
    printf("\tIssuer: %s\n", issuer);
    
    free(subject); // free the malloc'ed string
    free(issuer); // free the malloc'ed string
    X509_free(cert); // free the malloc'ed certificate copy
    }
    else
    printf("[-] No client's certificates\n");
    return;
}

void start_proxy(int port) {
    const char *certFile, *keyFile;
    
    ctx = initSSLContext(4);
    loadCertificates(ctx, NULL, NULL);

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