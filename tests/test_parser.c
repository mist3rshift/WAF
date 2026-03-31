#include "../inc/request_parser.h"

int main(void)
{
    String str = S("GET /index.html HTTP/1.1\r\nHost: coz.is\r\nUser-Agent: curl/7.81.0\r\n\r\n");

    Request req;
    if (parse_request(str, &req) < 0) {
        printf("Parsing failed\n");
        return -1;
    }

    printf("method: %.*s\n", UNPACK(req.method));
    printf("target: %.*s\n", UNPACK(req.target));
    printf("version: HTTP/%.1f\n", req.minor);
    printf("headers:\n");
    for (int i = 0; i < req.num_headers; i++)
        printf("name: %.*s, value: %.*s\n", UNPACK(req.headers[i].name), UNPACK(req.headers[i].value));

    return 0;
}

