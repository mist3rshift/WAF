#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "../inc/proxy.h"
#include "../inc/config.h"
#include "../inc/firewall.h"

int main(int argc, char* argv[]){
    if(argc < 2){
        printf("Usage : ./server <port>\n");
        exit(EXIT_FAILURE);
    }

    // Intecept Ctrl+C (SIGINT)
    signal(SIGINT, stop_waf_handler);

    int port = atoi(argv[1]);
    load_rules(DEFAULT_RULES_CONF_PATH);
    start_proxy(port);
    return 0;
}  