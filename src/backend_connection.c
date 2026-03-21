#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../lib/log.h"

int initialize_server_web_connection(void){
    int sockfd = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    struct sockaddr_in servaddr;
    if (sockfd < 0) {
        log_error("initialize_server_web_connection :Socket creation failed");
        return -1;

    }

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(80); // SERVER WEB PORT NUMBER

    // connect the client socket to server socket
    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr))
        != 0) {
        log_error("initialize_server_web_connection :connection with the server failed...\n");
        return -1;
    }
    else
        log_info("initialize_server_web_connection : connected to the server..\n");
        return sockfd;
}