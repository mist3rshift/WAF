#ifndef REQUEST_PARSER_H
#define REQUEST_PARSER_H

#include <stdio.h>
#include <stdbool.h>

#define MAX_HEADERS 128

#define S(X) (String) { (X), (int) sizeof(X)-1 }
#define UNPACK(X) (X).len, (X).ptr
#define COUNT(X) (sizeof(X) / sizeof((X)[0]))

typedef struct {
    char *src;
    int   len;
    int   cur;
} Scanner;

typedef struct {
    char *ptr;
    int   len;
} String;

typedef struct {
    String name;
    String value;
} Header;

typedef struct {
    String method;
    String target;
    float  minor;
    int    num_headers;
    Header headers[MAX_HEADERS];
} Request;

bool is_digit(char c);
bool is_alpha(char c);
bool is_tchar(char c);
int parse_method(Scanner *s, String *method);
int parse_target(Scanner *s, String *target);
float parse_version(Scanner *s, float *minor);
int parse_header(Scanner *s, Header *header);
int parse_header_list(Scanner *s, Header *headers, int max_headers);
int parse_request(String src, Request *req);

#endif