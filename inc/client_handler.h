#ifndef CLIENT_HANDLER_H
#define CLIENT_HANDLER_H

#include <netinet/in.h>
#include <openssl/ssl.h>

typedef struct {
    int client_fd;
    struct sockaddr_in client_addr;
    unsigned long thread_id;
    SSL *ssl; // ← ajouter ça
} ClientArgs;

void showCerts_client(SSL* ssl);
void handle_client(int client_sock, SSL *ssl);
void* handle_client_thread(void *args);
void cleanup_client_session(int client_sock, int web_server_sock, ClientArgs *client_args);
#endif