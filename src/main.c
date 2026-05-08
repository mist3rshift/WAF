#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "../inc/proxy.h"
#include "../inc/config.h"
#include "../inc/firewall.h"
#include "../lib/log.h"

int main(int argc, char* argv[]){
    if(argc < 2){
        printf("Usage : ./server <port>\n");
        exit(EXIT_FAILURE);
    }

    // Intecept Ctrl+C (SIGINT)
    signal(SIGINT, stop_waf_handler);

    int port = atoi(argv[1]);
    int loaded = load_rules(DEFAULT_RULES_CONF_PATH);
    if (loaded <= 0) {
        log_error(" Failed to load rules from %s (Count: %d)\n", 
                DEFAULT_RULES_CONF_PATH, loaded);
        // Do not start the proxy if we are blind
        exit(EXIT_FAILURE); 
    }
    log_info(" Successfully loaded %d rules.\n", loaded);
    start_proxy(port);
    return 0;
}  