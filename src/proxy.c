#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../lib/log.h"
#include "../inc/proxy.h"
#include "../inc/config.h"
#include "../inc/client_handler.h"

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

void start_proxy(int port) {
    int proxy_socket = initialise_proxy_socket(port);
    struct sockaddr_in client_addr;
    socklen_t addr_size = sizeof(client_addr);

    log_info("start_proxy : WAF à l'écoute sur le port %d...\n", port);

    while(1) {
        
        int client_sock = accept(proxy_socket, (struct sockaddr *)&client_addr, &addr_size);
        log_info("start_proxy : client socket %d accepted\n", client_sock);
        if (client_sock < 0) {
            log_error("start_proxy :Accept failed");
            continue; // waiting for customer
        }

        // OPTION A : Passage direct (Single-thread pour tester le MVP)
        handle_client(client_sock,proxy_socket); 
        
        // OPTION B : Passage au thread (Plus tard)
        // pthread_create(..., handle_client, (void*)&client_sock);
    }
}

int relay_stream(int socket_recv, int socket_to_write) {
    char buffer[BUFFER_SIZE];
    int bytes_read;

    // On boucle tant que le serveur envoie des données
    while ((bytes_read = recv(socket_recv, buffer, sizeof(buffer), 0)) > 0) {
        log_debug("relay_stream : reçu %d octets\n : message : %s", bytes_read,buffer);
        // On renvoie exactement ce qu'on a reçu au client
        if (send(socket_to_write, buffer, bytes_read, 0) < 0) {
            log_error("relay_stream : échec de l'envoi au client");
            break;
        }
    }

    if (bytes_read < 0) {
        log_error("relay_stream : erreur de lecture sur le serveur web");
    }
    return 0;
}