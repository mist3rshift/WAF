#ifndef PROXY_H
#define PROXY_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

int initialise_proxy_socket(int port);
void makekCert(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days);
SSL_CTX* initSSLContext();
void loadCertificates(SSL_CTX* ctx, const char* certFile, const char* keyFile);
void showCerts(SSL* ssl);
void start_proxy(int port);
int relay_stream(int socket_recv, int socket_to_write);
void stop_waf_handler(int signum);
#endif