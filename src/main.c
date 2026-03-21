#include <stdio.h>
#include <stdlib.h>
#include "../inc/proxy.h"

int main(int argc, char* argv[]){
    if(argc < 2){
        printf("Usage : ./server <port>\n");
        exit(EXIT_FAILURE);
    }
    int port = atoi(argv[1]);
    start_proxy(port);
    return 0;
}  