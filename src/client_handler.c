#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "../inc/config.h"
#include "../inc/client_handler.h"
#include "../lib/log.h"
#include "../inc/backend_connection.h"
#include "../inc/proxy.h"

void handle_client(int client_sock){
    char buffer[BUFFER_SIZE]; 

    // 3. Connexion to web server  (Upstream)
    int web_server_sock = initialize_server_web_connection();
    if (web_server_sock < 0) {
        const char *response = "HTTP/1.1 503 OK\r\nContent-Length: 23\r\n\r\nWeb Server unreachable \n";
        send(client_sock, response, strlen(response), 0);
        close(client_sock);
        return;
    }


    //Loop if message to long 
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

    
    close(client_sock);
    close(web_server_sock);
}

void* handle_client_thread(void *args) {
    pthread_detach(pthread_self()); // Detach the thread to allow for automatic resource cleanup
    //Extract client information from args
    ClientArgs *client_args = (ClientArgs *)args;
    int client_sock = client_args->client_fd;
    struct sockaddr_in client_addr = client_args->client_addr;
    pthread_t thisThread = pthread_self();
    unsigned long thread_id = (unsigned long) thisThread; // Use thread ID for logging
    
    log_info("handle_client_thread : thread %lu handling client socket %d\n", thread_id, client_sock);

    char buffer[BUFFER_SIZE]; 
    int web_server_sock = -1; // I,itialize to -1 to indicate no connection yet

    // 3. Connexion tp web server (Upstream)
    web_server_sock = initialize_server_web_connection();
    if (web_server_sock < 0) {
        
        const char *response = "HTTP/1.1 503 OK\r\nContent-Length: 23\r\n\r\nWeb Server unreachable \n";
        send(client_sock, response, strlen(response), 0);
        cleanup_client_session(client_sock, web_server_sock, client_args);
        log_error("handle_client_thread : failed to connect to web server for thread %lu\n", thread_id);
        pthread_exit(NULL);
    }


    //Loop if message to long
    int bytes_read = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read <= 0) {
        log_error("handle_client : no bytes received \n");
        cleanup_client_session(client_sock, web_server_sock, client_args);
        pthread_exit(NULL);
    }
    buffer[bytes_read] = '\0';

    //if(is_malicious(buffer))

    
    //send to web server 
    send(web_server_sock,buffer,sizeof(buffer)-1,0);
    
    //relay web server response to  client
    relay_stream(web_server_sock,client_sock);

    
    log_debug("handle_client_thread : closing connection for thread %lu\n", thread_id);
    cleanup_client_session(client_sock, web_server_sock, client_args);
    log_debug("handle_client_thread : thread %d exiting\n", thread_id);
    pthread_exit(NULL);
}


void cleanup_client_session(int client_fd, int web_fd,ClientArgs *client_args) {
    if (client_fd >= 0) {
        close(client_fd);
        log_debug("Client socket %d closed.", client_fd);
    }
    
    if (web_fd >= 0) {
        close(web_fd);
        log_debug("Web server socket %d closed.", web_fd);
    }

    if (client_args != NULL) {
        free(client_args);
        log_debug("Memory for client_args freed.");
    }
}


