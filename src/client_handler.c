#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../inc/config.h"
#include "../inc/client_handler.h"
#include "../lib/log.h"
#include "../inc/backend_connection.h"
#include "../inc/proxy.h"

void handle_client(int client_sock, int proxy_socket){
    char buffer[BUFFER_SIZE]; 

    // 3. Connexion au serveur web (Upstream)
    int web_server_sock = initialize_server_web_connection();
    if (web_server_sock < 0) {
        // Optionnel : Envoyer une erreur 502 Bad Gateway ici
        const char *response = "HTTP/1.1 502 OK\r\nContent-Length: 23\r\n\r\nWeb Server unreachable \n";
        send(client_sock, response, strlen(response), 0);
        close(client_sock);
        return;
    }


    //Faire boucle si message trop grand
    int bytes_read = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read <= 0) {
        log_error("handle_client : no bytes received \n");
        close(client_sock);
        return;
    }
    buffer[bytes_read] = '\0';

    //if(is_malicious(buffer))

    
    //send to web server 
    send(web_server_sock,buffer,sizeof(buffer)-1,0);
    
    //relay web server response to  client
    relay_stream(web_server_sock,client_sock);

    
    //Default response
    //const char *response = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World \n";
    //send(client_sock, response, strlen(response), 0);
    close(client_sock);
    close(web_server_sock);
}