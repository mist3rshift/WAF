#ifndef CLIENT_HANDLER_H
#define CLIENT_HANDLER_H


typedef struct {
    int client_fd;
    struct sockaddr_in client_addr;
    unsigned long thread_id;
    SSL *ssl; // ← ajouter ça
} ClientArgs;

SSL_CTX* initSSLContext(int ctxMethod);
void showCerts(SSL* ssl);
void handle_client(int client_sock);
void* handle_client_thread(void *args);
void cleanup_client_session(int client_sock, int web_server_sock, ClientArgs *client_args);
#endif