#ifndef PROXY_H
#define PROXY_H

int initialise_proxy_socket(int port);
void callbackGeneratingKey(int p, int n, void *arg);
void makekCert(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days);
SSL_CTX* initSSLContext(int ctxMethod);
void loadCertificates(SSL_CTX* ctx, const char* certFile, const char* keyFile);
void showCerts(SSL* ssl);
void routine(SSL* ssl);
void start_proxy(int port);
int relay_stream(int socket_recv, int socket_to_write);
void stop_waf_handler(int signum);
#endif