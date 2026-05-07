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

static void callbackGeneratingKey(int p, int n, void *arg){
    char c='B';
    if (p == 0) c = '.'; // generating key...
    if (p == 1) c = '+'; // near the end of generation...
    if (p == 2) c = '*'; // rejecting current random generation...
    if (p == 3) c = '\n'; // key generated
    fputc(c, stderr); // print generation state
}

void makekCert(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days){
    X509 *x;
    EVP_PKEY *pk;
    RSA *rsa;
    X509_NAME *name = NULL;
    
    if((pkeyp == NULL) || (*pkeyp == NULL)){
        if((pk = EVP_PKEY_new()) == NULL)
        abort();
    } else
    pk= *pkeyp;
    if((x509p == NULL) || (*x509p == NULL)){
        if ((x = X509_new()) == NULL)
        abort();
    } else
    x= *x509p;
    
    // create RSA key
    rsa = RSA_generate_key(bits, RSA_F4, callbackGeneratingKey, NULL);
    if(!EVP_PKEY_assign_RSA(pk, rsa))
    abort();
    rsa = NULL;
    
    X509_set_version(x, 2); // why not 3 ?
    ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
    X509_gmtime_adj(X509_get_notBefore(x), 0); // define validation begin cert
    X509_gmtime_adj(X509_get_notAfter(x), (long)60*60*24*days); // define validation end cert
    X509_set_pubkey(x, pk); // define public key in cert
    name = X509_get_subject_name(x);
    
    // This function creates and adds the entry, working out the
    // correct string type and performing checks on its length.
    // Normally we'd check the return value for errors...
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"XX", -1, -1, 0); // useless if more anonymity needed
    X509_NAME_add_entry_by_txt(name,"CN", MBSTRING_ASC, (const unsigned char*)"ASRAT", -1, -1, 0); // useless if more anonymity needed
    
    // Its self signed so set the issuer name to be the same as the subject.
    X509_set_issuer_name(x, name);
    
    if(!X509_sign(x, pk, EVP_md5())) // secured more with sha1? md5/sha1? sha256?
    abort();
    
    *x509p = x;
    *pkeyp = pk;
    return;
}

SSL_CTX* initSSLContext(int ctxMethod){
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    
    SSL_library_init(); // initialize the SSL library
    SSL_load_error_strings(); // bring in and register error messages
    OpenSSL_add_all_algorithms(); // load usable algorithms
    
    switch(ctxMethod){ // create new client-method instance
        case 1 :
        method = TLSv1_server_method();
        printf("[+] Use TLSv1 method.\n");
        break;
        // SSLv2 isn't sure and is deprecated, so the latest OpenSSL version on Linux delete his implementation.
        /*case 2 :
        method = SSLv2_server_method();
        printf("[+] Use SSLv2 method.\n");
        break;*/
        case 3 :
        method = SSLv3_server_method();
        printf("[+] Use SSLv3 method.\n");
        break;
        case 4 :
        method = SSLv23_server_method();
        printf("[+] Use SSLv2&3 method.\n");
        break;
        default :
        method = SSLv23_server_method();
        printf("[+] Use SSLv2&3 method.\n");
        }
    
    ctx = SSL_CTX_new(method); // create new context from selected method
    if(ctx == NULL){
    ERR_print_errors_fp(stderr);
    abort();
    }
    return ctx;
}

void loadCertificates(SSL_CTX* ctx, const char* certFile, const char* keyFile){
    // The server private key in PEM format, if internals required
    /*const char *keyBuffer = "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDP1SC2T/+NW59H\n"
    "CYF0mzkoFcObGUAkoK7mvemFk2P99FLcKbqYKZZDMLVBg+tLU12kuIefYrC4G8F7\n"
    "K8WReTZ+ZBWI1h+gEBhilZ0O4+XXoww2tjVyuHNe5twSxOhRYvoPNSKMLPR70Oij\n"
    "b4nHSyu0a7JHAWvEdpk7HIeWugKYbY8ss58iCmkWGcrop/od6SPW12W+ugAyDGD9\n"
    "F1Otrmb+T3KQPadlPgGdNprvVXHjk+eS1RcwOsT630usogl1JqhoAT4ViQvxDP0J\n"
    "LEffPvG2Iow2WoRtjLGfKqGinhtrLyuht5s3XBzm05kHYNVDc1vkWPvk4PuoIfTp\n"
    "ezrxuMR5AgMBAAECggEADV6wlAnhbr6OKIu8ADxcGPANfVTKg5Cyr7VX6Hfq3tNw\n"
    "4SjuEAvc1sWzY1uRL29VfttAHkjDBZUDhWDzfMBHeSoHGJ5tumZOq0jkqaiPiKe8\n"
    "iWh/V7n18gz3610vdMzhOUk5x7q8n5p43Mq4GlIDpb+n4Fl/DUxz3xGex1t//z4v\n"
    "W7U1j+dKxiZGaNz2dyVVM7eHaynvEE4QL8i4msjhmrFSItqjF/0M/CJ0oEPPb2VL\n"
    "6GLSfqCcjBzt0Sy93gVNhxO+KjMpumB1a9omDxBkTO4HF4xoDojrtkgYXaUx3uKk\n"
    "Gc35xLoOdkn/pNDDzGzQT+xWYOO6IBxJGj/INvnIAQKBgQDwdVsC02z0Pb4JrlcM\n"
    "KRBGyJetxxQguiZ3TYMIGMMP/fQZn3uofmWxNGPbk20VmDXXtZFsCJG7zrFVOUe3\n"
    "eXIPjE2ho80aPAMWeiPAMkivhj0OnPHTg5sof75uH5F9zPerw7kgcwZMFPZk/Za0\n"
    "53gxjakIZo2mlrtaomZLD/U+2QKBgQDdQ/EQlMG5+sjGn6MQrqpzlIT+PYQ4OmFE\n"
    "p8B6AKtwC1oVKkY/1dWVUQ33DqTbXv8i8zN2mplMaFM/6rJNcY4BhKwBm+pW5XuV\n"
    "LHLMGGkubues3bCb2OHax8DOm/i6hDJ14cEORsZSA2Jt6qzxaQ9HrtCZy29S5FIg\n"
    "cFGCLHNuoQKBgAIe5tiViMZ2rPBk6zueORiGuF+9+712JtSyiE9P+Jhxgu+e6nZH\n"
    "9xmi/qZ3HGUuXHs0jL3JLY/ceM/pm2pQ1eKxOBYO3cY3dUeDeEE/sEhsBKnWVIOr\n"
    "C3lF9yX9fUkAv8ZyCXXxzcJqBOpLGkMqL3Mwbqc2UFWBytE30XMkBuOxAoGBAI8l\n"
    "qGzAwIBwpboShy2AwteZq1zMMaEq68i9+oEzs7X+Mh5lRiOAVPiQAsfmGnOuBsP2\n"
    "sUG3DRxolgtQ7F+76lJDIgC8fSQQvR4qLm6qEEoxCANHPT3mV1/yQWOpdoY8hmTL\n"
    "U9nHogBnHiPcYlygSnlmuJ/3BCONgTBpWeIsndVhAoGAOFpnITiCmUFc5AUaxglZ\n"
    "fz4fC+Mt4SF4XGFUtL8feGN4XGXHU6lQVQqu1yaRpYjSTabq6V6LLvVOh1sb+qZw\n"
    "sSB4hC5C+VjjIBScsaN0pytFdL0+FeRaGPVBUs/yBWzfhi6Lm9vE8ebE0fMxr7b5\n"
    "gw4qJCTvXYDZ8ZOIwG4YRRs=\n"
    "-----END PRIVATE KEY-----\n";
    // The server certificat containing public key in PEM format
    const char *certBuffer = "-----BEGIN CERTIFICATE-----\n"
    "MIIDiTCCAnGgAwIBAgIJAK0drhMsLqg2MA0GCSqGSIb3DQEBBQUAMFsxCzAJBgNV\n"
    "BAYTAlhYMQowCAYDVQQIDAFYMQowCAYDVQQHDAFYMQowCAYDVQQKDAFYMQowCAYD\n"
    "VQQLDAFYMQowCAYDVQQDDAFYMRAwDgYJKoZIhvcNAQkBFgFYMB4XDTEyMDMwMTEz\n"
    "NDcwM1oXDTEyMDMzMTEzNDcwM1owWzELMAkGA1UEBhMCWFgxCjAIBgNVBAgMAVgx\n"
    "CjAIBgNVBAcMAVgxCjAIBgNVBAoMAVgxCjAIBgNVBAsMAVgxCjAIBgNVBAMMAVgx\n"
    "EDAOBgkqhkiG9w0BCQEWAVgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB\n"
    "AQDP1SC2T/+NW59HCYF0mzkoFcObGUAkoK7mvemFk2P99FLcKbqYKZZDMLVBg+tL\n"
    "U12kuIefYrC4G8F7K8WReTZ+ZBWI1h+gEBhilZ0O4+XXoww2tjVyuHNe5twSxOhR\n"
    "YvoPNSKMLPR70Oijb4nHSyu0a7JHAWvEdpk7HIeWugKYbY8ss58iCmkWGcrop/od\n"
    "6SPW12W+ugAyDGD9F1Otrmb+T3KQPadlPgGdNprvVXHjk+eS1RcwOsT630usogl1\n"
    "JqhoAT4ViQvxDP0JLEffPvG2Iow2WoRtjLGfKqGinhtrLyuht5s3XBzm05kHYNVD\n"
    "c1vkWPvk4PuoIfTpezrxuMR5AgMBAAGjUDBOMB0GA1UdDgQWBBRG76BYshU93k3q\n"
    "hy6gIpMl/VUDhTAfBgNVHSMEGDAWgBRG76BYshU93k3qhy6gIpMl/VUDhTAMBgNV\n"
    "HRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQBCGmmyVt9gRJ0fuWh9o5MnT70m\n"
    "nwbt0fM3Z6AO/Gkc0fkc6H4pZ3tnEtubtXBBm24wMFfXutcXFAjZMk0OTCPj5U8I\n"
    "0/yjk5zuBdgktIFUTjs4Os/Ct2wvIfIiOm/WeL3FZOWli/HOX1PqjbeF/HXN+069\n"
    "31U++ajDzM0uDFGc7dEPTXTEuE7w81696n9PTF0PSLt3/xIOwkMx28Wykc9XKgAp\n"
    "MztGxeEtyb32ib+zL7UhEyuDHnW4haC8QsjG1QLpESTMMASbRe6QxrYxuMFjkf+g\n"
    "FMw9jUYsThZropV2gFipcltT63ncyk0/W8gj1zmF6QsC46r1MFPUfnc/I6dx\n"
    "-----END CERTIFICATE-----\n";*/
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    // RSA *rsa = NULL; // if internal private key and certificat required
    //BIO *cbio, *kbio; // if internal private key and certificat required
    
    if(certFile == NULL || keyFile == NULL){
    
    /*
    // if internal certificat and private key required
    printf("[*] Loading internal server's certificat and private key.\n");
    cbio = BIO_new_mem_buf((void*)certBuffer, -1);
    PEM_read_bio_X509(cbio, &cert, 0, NULL);
    SSL_CTX_use_certificate(ctx, cert);
    kbio = BIO_new_mem_buf((void*)keyBuffer, -1);
    PEM_read_bio_RSAPrivateKey(kbio, &rsa, 0, NULL);
    SSL_CTX_use_RSAPrivateKey(ctx, rsa);
    */
    
    printf("[*] Generate random server's certificat and private key.\n");
    makekCert(&cert, &pkey, 2048, 0, 0);
    SSL_CTX_use_certificate(ctx, cert);
    SSL_CTX_use_PrivateKey(ctx, pkey);
    
    // set the local certificate from certFile if certFile specified
    // set the private key from keyFile (may be the same as certFile) if specified
    } else if(SSL_CTX_use_certificate_file(ctx, certFile, SSL_FILETYPE_PEM) <= 0 ||
    SSL_CTX_use_RSAPrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM) <= 0){
    ERR_print_errors_fp(stderr);
    abort();
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

void routine(SSL* ssl, int socket_recv){
    char buf[1024], reply[1024];
    int sock, bytes;
    const char* echo = "Enchante %s, je suis ServerName.\n";
    
    if(SSL_accept(ssl) == -1) // accept SSL/TLS connection
    ERR_print_errors_fp(stderr);
    else{
    printf("[+] Cipher used : %s\n", SSL_get_cipher(ssl));
    showCerts(ssl); // get any client certificates
    bytes = recv(socket_recv, buf, sizeof(buf), 0); // read data from client request
    if(bytes > 0){
    buf[bytes] = 0;
    printf("[+] Client data received : %s\n", buf);
    sprintf(reply, echo, buf); // construct response
    SSL_write(ssl, reply, strlen(reply)); // send response
    } else {
    switch(SSL_get_error(ssl, bytes)){
    case SSL_ERROR_ZERO_RETURN :
    printf("SSL_ERROR_ZERO_RETURN : ");
    break;
    case SSL_ERROR_NONE :
    printf("SSL_ERROR_NONE : ");
    break;
    case SSL_ERROR_SSL:
    printf("SSL_ERROR_SSL : ");
    break;
    }
    ERR_print_errors_fp(stderr);
    }
    
    }
    sock = SSL_get_fd(ssl); // get traditionnal socket connection from SSL connection
    SSL_shutdown(ssl);
    SSL_free(ssl); // release SSL connection state
    CLOSESOCKET(sock); // close socket
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
    SOCKLEN_T len = sizeof(addr);

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
        // passer ssl dans client_args
        client_args->ssl = ssl;

        // OPTION A : Direct connection (Single-thread for the MVP)
        //handle_client(client_sock); 
        
        // OPTION B : Use threads to handle multiple clients concurrently
        ClientArgs *client_args = calloc(1, sizeof(ClientArgs));
        client_args->client_fd = client_sock;
        client_args->client_addr = client_addr;
        client_args->thread_id = 0; // will be set in the thread function
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
        close(proxy_socket);
        log_info("Main proxy socket closed.");
        SSL_CTX_free(ctx); 
    }

    // Mutex cleanup if needed
    // pthread_mutex_destroy(&log_mutex);

    log_info("WAF stopped properly. Goodbye!");
    free_rules();
    exit(0);
}