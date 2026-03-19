#include "../inc/server.h"



int create_server_socket(int port){
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
    int proxy_socket = create_server_socket(port);
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


void handle_client(int client_sock, int proxy_socket){
    char buffer[BUFFER_SIZE]; 

    //Faire boucle si message trop grand
    int bytes_read = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read <= 0) {
        log_error("handle_client : no bytes received \n");
        close(client_sock);
        return;
    }
    buffer[bytes_read] = '\0';

    //if(is_malicious(buffer))


    // 3. Connexion au serveur web (Upstream)
    int web_server_sock = initialize_server_web_connection();
    if (web_server_sock < 0) {
        // Optionnel : Envoyer une erreur 502 Bad Gateway ici
        close(client_sock);
        return;
    }

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

int relay_stream(int web_socket, int client_socket) {
    char buffer[BUFFER_SIZE];
    int bytes_read;

    // On boucle tant que le serveur envoie des données
    while ((bytes_read = recv(web_socket, buffer, sizeof(buffer), 0)) > 0) {
        log_debug("relay_stream : reçu %d octets\n", bytes_read);
        
        // On renvoie exactement ce qu'on a reçu au client
        if (send(client_socket, buffer, bytes_read, 0) < 0) {
            log_error("relay_stream : échec de l'envoi au client");
            break;
        }
    }

    if (bytes_read < 0) {
        log_error("relay_stream : erreur de lecture sur le serveur web");
    }
    return 0;
}


int main(int argc, char* argv[]){
    if(argc < 2){
        printf("Usage : ./server <port>\n");
        exit(EXIT_FAILURE);
    }
    int port = atoi(argv[1]);
    start_proxy(port);
    return 0;
}  