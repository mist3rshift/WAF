#include "headers/server.h"
#include <arpa/inet.h>

int create_server_socket(int port){
    //AF_INET: Specifies IPv4.
    int server_fd = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if (server_fd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);

    }

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; // Bind to any IP
    //Converts the port to network byte order.
    address.sin_port = htons(port);       // Use the port parameter
    

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    
    if (listen(server_fd, MAX_CLIENT) < 0) {
    perror("Listen failed");
    exit(EXIT_FAILURE);
    }

    return server_fd;
}
void handle_client(int client_sock){

}

int main(int argc,char* argv){
    if(argc < 2){
        printf("Usage : ./server <port>\n");
        exit(EXIT_FAILURE);
    }
    return 0;
}