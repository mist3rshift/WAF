//Parsing des requêtes HTTP (extraction method, path, headers, body)
#include "../inc/request_parser.h"

bool is_digit(char c)
{
    return c >= '0' && c <= '9';
}

bool is_alpha(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

bool is_tchar(char c)
{
    return c == '!' || c == '#' || c == '$' || c == '%' || c == '&'
        || c == '\'' || c == '*' || c == '+' || c == '-' || c == '.'
        || c == '^' || c == '_' || c == '`' || c == '|' || c == '~'
        || is_digit(c) || is_alpha(c);
}

bool consume_str(Scanner *s, String x)
{
    if (x.len == 0)
        return false;

    if (x.len > s->len - s->cur)
        return false;

    for (int i = 0; i < x.len; i++)
        if (s->src[s->cur+i] != x.ptr[i])
            return false;

    s->cur += x.len;
    return true;
}

int parse_method(Scanner *s, String *method)
{
    int method_off = s->cur;

    // Consume a tchar or fail
    if (s->cur == s->len || !is_tchar(s->src[s->cur]))
        return -1; // Error! Missing token
    s->cur++;

    // Consume additional tchars following the first one
    while (s->cur < s->len && is_tchar(s->src[s->cur]))
        s->cur++;

    // Make a substring of the method
    *method = (String) {
        s->src + method_off,
        s->cur - method_off
    };

    // Consume a space or fail
    if (s->cur == s->len || s->src[s->cur] != ' ')
        return -1;
    s->cur++;

    // All good!
    return 0;
}

int parse_target(Scanner *s, String *target)
{
    int off = s->cur;

    while (s->cur < s->len && s->src[s->cur] != ' ')
        s->cur++;

    *target = (String) {
        s->src + off,
        s->cur - off,
    };

    if (s->cur == s->len)
        return -1;
    s->cur++;

    return 0;
}

float parse_version(Scanner *s, float *minor)
{
    if (consume_str(s, S("HTTP/1.0\r\n"))) {
        *minor = 1.0;
        return 0;
    }

    if (consume_str(s, S("HTTP/1.1\r\n"))) {
        *minor = 1.1;
        return 0;
    }

    if (consume_str(s, S("HTTP/2.0\r\n"))) {
        *minor = 2.0;
        return 0;
    }

    return -1;
}

bool is_vchar(char c)
{
    return c >= ' ' && c <= '~';
}

int parse_header(Scanner *s, Header *header)
{
    // Parse the name

    int name_off = s->cur;
    if (s->cur == s->len || !is_tchar(s->src[s->cur]))
        return -1;
    s->cur++;

    while (s->cur < s->len && is_tchar(s->src[s->cur]))
        s->cur++;
    header->name = (String) { s->src + name_off, s->cur - name_off };

    // Consume the separator
    if (s->cur == s->len || s->src[s->cur] != ':')
        return -1;
    s->cur++;

    // Consume whitespace preceding the value
    while (s->cur < s->len && (s->src[s->cur] == ' ' || s->src[s->cur] == '\t'))
        s->cur++;

    // Parse the value

    int value_off = s->cur;

    // Consume all VCHARs and spaces
    while (s->cur < s->len && (is_vchar(s->src[s->cur]) || s->src[s->cur] == ' ' || s->src[s->cur] == '\t'))
        s->cur++;

    // If the body ended with some spaces, remove them. Note how this loop
    // doesn't have bound checks. We can do this because we know the header
    // contains at least one tchar
    while (s->src[s->cur] == ' ' || s->src[s->cur] == '\t')
        s->cur--;

    // Make a slice for the value
    header->value = (String) { s->src + value_off, s->cur - value_off };

    // Consume any spaces that follow the value
    while (s->cur < s->len && (s->src[s->cur] == ' ' || s->src[s->cur] == '\t'))
        s->cur++;

    // Consume the CRLF following the header field

    if (1 >= s->len - s->cur
        || s->src[s->cur+0] != '\r'
        || s->src[s->cur+1] != '\n')
        return -1;
    s->cur += 2;

    return 0;
}

int parse_header_list(Scanner *s, Header *headers, int max_headers)
{
    int num_headers = 0;
    while (!consume_str(s, S("\r\n"))) {

        if (num_headers == max_headers)
            return -1;

        int ret = parse_header(s, &headers[num_headers]);
        if (ret < 0)
            return -1;

        num_headers++;
    }

    return num_headers;
}

int parse_request(String src, Request *req)
{
    Scanner s = { src.ptr, src.len, 0 };

    if (parse_method(&s, &req->method) < 0)
        return -1;

    if (parse_target(&s, &req->target) < 0)
        return -1;

    if (parse_version(&s, &req->minor) < 0)
        return -1;

    int ret = parse_header_list(&s, req->headers, (int) COUNT(req->headers));
    if (ret < 0)
        return -1;
    req->num_headers = ret;

    return 0;
}