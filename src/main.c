#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "../inc/proxy.h"

int main(int argc, char* argv[]){
    if(argc < 2){
        printf("Usage : ./server <port>\n");
        exit(EXIT_FAILURE);
    }

    // Intecept Ctrl+C (SIGINT)
    signal(SIGINT, stop_waf_handler);

    int port = atoi(argv[1]);
    start_proxy(port);
    return 0;
}  