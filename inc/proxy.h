#ifndef PROXY_H
#define PROXY_H
int initialise_proxy_socket(int port);
void start_proxy(int port);
int relay_stream(int socket_recv, int socket_to_write);
void stop_waf_handler(int signum);
#endif