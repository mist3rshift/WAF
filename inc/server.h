#ifndef SERVER_H
#define SERVER_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "../lib/log.h"
#include <arpa/inet.h>
#define MAX_CLIENT 200
#define BUFFER_SIZE 2048


int create_server_socket(int port);
void start_proxy(int port);
void handle_client(int client_sock, int proxy_socket);
int initialize_server_web_connection(void);
int relay_stream (int web_socket,int client_socket);
int main(int argc, char* argv[]);

#endif
