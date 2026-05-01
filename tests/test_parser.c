#include "../inc/request_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define TEST_PASSED printf("✓ %s passed\n", __func__)
#define TEST_FAILED printf("✗ %s FAILED\n", __func__); return 1
#define ASSERT_EQ(a, b) if ((a) != (b)) { printf("  Assertion failed: %d != %d\n", (int)(a), (int)(b)); TEST_FAILED; }
#define ASSERT_TRUE(cond) if (!(cond)) { printf("  Assertion failed: condition is false\n"); TEST_FAILED; }
#define ASSERT_FALSE(cond) if ((cond)) { printf("  Assertion failed: condition is true\n"); TEST_FAILED; }
#define ASSERT_STR_EQ(a, b, len) if (strncmp((a), (b), (len)) != 0) { printf("  String comparison failed\n"); TEST_FAILED; }
#define ASSERT_FLOAT_EQ(a, b) if (fabsf((float)(a) - (float)(b)) > 0.01f) { printf("  Float assertion failed: %f != %f\n", (float)(a), (float)(b)); TEST_FAILED; }
#include <math.h>

// ============================================================================
// BASIC GET REQUEST TESTS
// ============================================================================

int test_simple_get_request() {
    const char *request_str = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.method.len, 3);
    ASSERT_STR_EQ(req.method.ptr, "GET", 3);
    ASSERT_EQ(req.target.len, 1);
    ASSERT_STR_EQ(req.target.ptr, "/", 1);
    ASSERT_FLOAT_EQ(req.minor, 1.1);
    ASSERT_EQ(req.num_headers, 1);
    ASSERT_EQ(req.headers[0].name.len, 4);
    ASSERT_STR_EQ(req.headers[0].name.ptr, "Host", 4);
    
    TEST_PASSED;
    return 0;
}

int test_get_with_query_string() {
    const char *request_str = "GET /search?q=test&page=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.method.len, 3);
    ASSERT_STR_EQ(req.method.ptr, "GET", 3);
    ASSERT_EQ(req.target.len, 21);
    ASSERT_STR_EQ(req.target.ptr, "/search?q=test&page=1", 21);
    
    TEST_PASSED;
    return 0;
}

int test_get_with_complex_query() {
    const char *request_str = "GET /api/users?id=123&name=John%20Doe&sort=asc HTTP/1.0\r\nHost: api.example.com\r\n\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.method.len, 3);
    ASSERT_EQ(req.minor, 1.0);
    
    TEST_PASSED;
    return 0;
}

// ============================================================================
// POST REQUEST TESTS
// ============================================================================

int test_simple_post_request() {
    const char *request_str = "POST /api/data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 13\r\n\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.method.len, 4);
    ASSERT_STR_EQ(req.method.ptr, "POST", 4);
    ASSERT_EQ(req.target.len, 9);
    ASSERT_STR_EQ(req.target.ptr, "/api/data", 9);
    ASSERT_FLOAT_EQ(req.minor, 1.1);
    ASSERT_EQ(req.num_headers, 2);
    
    TEST_PASSED;
    return 0;
}

int test_post_with_content_type() {
    const char *request_str = "POST /submit HTTP/1.1\r\n"
                              "Host: example.com\r\n"
                              "Content-Type: application/json\r\n"
                              "Content-Length: 27\r\n"
                              "\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.method.len, 4);
    ASSERT_EQ(req.num_headers, 3);
    
    // Check Content-Type header
    ASSERT_EQ(req.headers[1].name.len, 12);
    ASSERT_STR_EQ(req.headers[1].name.ptr, "Content-Type", 12);
    
    TEST_PASSED;
    return 0;
}

int test_post_form_urlencoded() {
    const char *request_str = "POST /login HTTP/1.1\r\n"
                              "Host: example.com\r\n"
                              "Content-Type: application/x-www-form-urlencoded\r\n"
                              "Content-Length: 32\r\n"
                              "\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.method.len, 4);
    ASSERT_EQ(req.num_headers, 3);
    
    TEST_PASSED;
    return 0;
}

// ============================================================================
// MULTIPLE HEADERS TESTS
// ============================================================================

int test_multiple_headers() {
    const char *request_str = "GET / HTTP/1.1\r\n"
                              "Host: example.com\r\n"
                              "User-Agent: Mozilla/5.0\r\n"
                              "Accept: text/html\r\n"
                              "Accept-Language: en-US\r\n"
                              "\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.num_headers, 4);
    ASSERT_EQ(req.headers[0].name.len, 4);
    ASSERT_EQ(req.headers[1].name.len, 10);
    ASSERT_EQ(req.headers[2].name.len, 6);
    ASSERT_EQ(req.headers[3].name.len, 15);
    
    TEST_PASSED;
    return 0;
}

int test_many_headers() {
    char buffer[4096];
    strcpy(buffer, "GET / HTTP/1.1\r\n");
    
    // Add 20 headers
    for (int i = 0; i < 20; i++) {
        char header_line[128];
        snprintf(header_line, sizeof(header_line), "X-Custom-Header-%d: value-%d\r\n", i, i);
        strcat(buffer, header_line);
    }
    strcat(buffer, "\r\n");
    
    Request req;
    String src = { buffer, (int)strlen(buffer) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.num_headers, 20);
    
    TEST_PASSED;
    return 0;
}

int test_max_headers_boundary() {
    char buffer[8192];
    strcpy(buffer, "GET / HTTP/1.1\r\n");
    
    // Add exactly MAX_HEADERS - 1 headers (to stay under the limit)
    for (int i = 0; i < MAX_HEADERS - 1; i++) {
        char header_line[128];
        snprintf(header_line, sizeof(header_line), "X-Header-%d: value\r\n", i);
        strcat(buffer, header_line);
    }
    strcat(buffer, "\r\n");
    
    Request req;
    String src = { buffer, (int)strlen(buffer) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.num_headers, MAX_HEADERS - 1);
    
    TEST_PASSED;
    return 0;
}

// ============================================================================
// HEADER VALUE TESTS
// ============================================================================

int test_header_with_spaces_in_value() {
    const char *request_str = "GET / HTTP/1.1\r\n"
                              "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                              "\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.num_headers, 1);
    // Value should include spaces but trim trailing
    ASSERT_TRUE(req.headers[0].value.len > 0);
    
    TEST_PASSED;
    return 0;
}

int test_header_with_special_characters() {
    const char *request_str = "GET / HTTP/1.1\r\n"
                              "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\r\n"
                              "\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.num_headers, 1);
    
    TEST_PASSED;
    return 0;
}

int test_header_with_tabs() {
    const char *request_str = "GET / HTTP/1.1\r\n"
                              "Host:\texample.com\r\n"
                              "\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.num_headers, 1);
    
    TEST_PASSED;
    return 0;
}

// ============================================================================
// HTTP VERSION TESTS
// ============================================================================

int test_http_version_1_0() {
    const char *request_str = "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.minor, 1.0);
    
    TEST_PASSED;
    return 0;
}

int test_http_version_1_1() {
    const char *request_str = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_FLOAT_EQ(req.minor, 1.1);
    
    TEST_PASSED;
    return 0;
}

int test_http_version_2_0() {
    const char *request_str = "GET / HTTP/2.0\r\nHost: example.com\r\n\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.minor, 2.0);
    
    TEST_PASSED;
    return 0;
}

// ============================================================================
// OTHER HTTP METHODS
// ============================================================================

int test_put_method() {
    const char *request_str = "PUT /resource HTTP/1.1\r\nHost: example.com\r\n\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.method.len, 3);
    ASSERT_STR_EQ(req.method.ptr, "PUT", 3);
    
    TEST_PASSED;
    return 0;
}

int test_delete_method() {
    const char *request_str = "DELETE /resource HTTP/1.1\r\nHost: example.com\r\n\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.method.len, 6);
    ASSERT_STR_EQ(req.method.ptr, "DELETE", 6);
    
    TEST_PASSED;
    return 0;
}

int test_patch_method() {
    const char *request_str = "PATCH /api/users/123 HTTP/1.1\r\nHost: example.com\r\n\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.method.len, 5);
    ASSERT_STR_EQ(req.method.ptr, "PATCH", 5);
    
    TEST_PASSED;
    return 0;
}

int test_options_method() {
    const char *request_str = "OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.method.len, 7);
    ASSERT_STR_EQ(req.method.ptr, "OPTIONS", 7);
    
    TEST_PASSED;
    return 0;
}

int test_head_method() {
    const char *request_str = "HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.method.len, 4);
    ASSERT_STR_EQ(req.method.ptr, "HEAD", 4);
    
    TEST_PASSED;
    return 0;
}

// ============================================================================
// LARGE DATA TESTS
// ============================================================================

int test_large_query_string() {
    char buffer[2048];
    strcpy(buffer, "GET /search?");
    
    // Generate a large query string
    for (int i = 0; i < 50; i++) {
        char param[64];
        snprintf(param, sizeof(param), "param%d=value%d&", i, i);
        strcat(buffer, param);
    }
    strcat(buffer, "end=1 HTTP/1.1\r\nHost: example.com\r\n\r\n");
    
    Request req;
    String src = { buffer, (int)strlen(buffer) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(req.target.len > 500);
    
    TEST_PASSED;
    return 0;
}

int test_large_header_value() {
    char buffer[2048];
    strcpy(buffer, "GET / HTTP/1.1\r\n");
    strcat(buffer, "X-Large-Header: ");
    
    // Add 1000 character header value
    for (int i = 0; i < 100; i++) {
        strcat(buffer, "0123456789");
    }
    strcat(buffer, "\r\n\r\n");
    
    Request req;
    String src = { buffer, (int)strlen(buffer) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(req.headers[0].value.len >= 1000);
    
    TEST_PASSED;
    return 0;
}

int test_many_query_parameters() {
    char buffer[4096];
    strcpy(buffer, "GET /api?");
    
    // Generate 100 query parameters
    for (int i = 0; i < 100; i++) {
        char param[64];
        snprintf(param, sizeof(param), "p%d=%d&", i, i * 2);
        strcat(buffer, param);
    }
    strcat(buffer, "final=1 HTTP/1.1\r\nHost: example.com\r\n\r\n");
    
    Request req;
    String src = { buffer, (int)strlen(buffer) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    
    TEST_PASSED;
    return 0;
}

// ============================================================================
// BORDER CASE / ERROR TESTS
// ============================================================================

int test_missing_method() {
    const char *request_str = " / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, -1);
    
    TEST_PASSED;
    return 0;
}

int test_missing_target() {
    const char *request_str = "GET HTTP/1.1\r\nHost: example.com\r\n\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, -1);
    
    TEST_PASSED;
    return 0;
}

int test_missing_http_version() {
    const char *request_str = "GET /\r\nHost: example.com\r\n\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, -1);
    
    TEST_PASSED;
    return 0;
}

int test_invalid_http_version() {
    const char *request_str = "GET / HTTP/3.0\r\nHost: example.com\r\n\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, -1);
    
    TEST_PASSED;
    return 0;
}

int test_missing_header_colon() {
    const char *request_str = "GET / HTTP/1.1\r\nHost example.com\r\n\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, -1);
    
    TEST_PASSED;
    return 0;
}

int test_missing_crlf_after_header() {
    const char *request_str = "GET / HTTP/1.1\r\nHost: example.com\nAnother: header\r\n\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, -1);
    
    TEST_PASSED;
    return 0;
}

int test_empty_request() {
    const char *request_str = "";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, -1);
    
    TEST_PASSED;
    return 0;
}

int test_only_method_no_space() {
    const char *request_str = "GET";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, -1);
    
    TEST_PASSED;
    return 0;
}

int test_root_path() {
    const char *request_str = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.target.len, 1);
    ASSERT_STR_EQ(req.target.ptr, "/", 1);
    
    TEST_PASSED;
    return 0;
}

int test_deep_path() {
    const char *request_str = "GET /api/v1/users/123/profile/settings HTTP/1.1\r\nHost: example.com\r\n\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.target.len, 34);
    
    TEST_PASSED;
    return 0;
}

int test_path_with_special_characters() {
    const char *request_str = "GET /api/users/john-doe_123 HTTP/1.1\r\nHost: example.com\r\n\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    
    TEST_PASSED;
    return 0;
}

int test_single_header() {
    const char *request_str = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.num_headers, 1);
    
    TEST_PASSED;
    return 0;
}

int test_case_sensitive_method() {
    const char *request_str = "get / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.method.len, 3);
    ASSERT_STR_EQ(req.method.ptr, "get", 3);
    
    TEST_PASSED;
    return 0;
}

int test_numeric_method() {
    const char *request_str = "G3T / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.method.len, 3);
    ASSERT_STR_EQ(req.method.ptr, "G3T", 3);
    
    TEST_PASSED;
    return 0;
}

int test_asterisk_target() {
    const char *request_str = "OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.target.len, 1);
    ASSERT_STR_EQ(req.target.ptr, "*", 1);
    
    TEST_PASSED;
    return 0;
}

// ============================================================================
// REAL-WORLD SCENARIOS
// ============================================================================

int test_real_world_json_post() {
    const char *request_str = "POST /api/users HTTP/1.1\r\n"
                              "Host: api.example.com\r\n"
                              "Content-Type: application/json\r\n"
                              "Content-Length: 58\r\n"
                              "Authorization: Bearer token123456789\r\n"
                              "Accept: application/json\r\n"
                              "\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.method.len, 4);
    ASSERT_EQ(req.num_headers, 5);
    
    TEST_PASSED;
    return 0;
}

int test_real_world_browser_get() {
    const char *request_str = "GET /search?q=nodejs&lang=en HTTP/1.1\r\n"
                              "Host: www.google.com\r\n"
                              "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\r\n"
                              "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                              "Accept-Language: en-US,en;q=0.5\r\n"
                              "Accept-Encoding: gzip, deflate\r\n"
                              "Connection: keep-alive\r\n"
                              "\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.num_headers, 6);
    
    TEST_PASSED;
    return 0;
}

int test_real_world_file_upload_form() {
    const char *request_str = "POST /upload HTTP/1.1\r\n"
                              "Host: example.com\r\n"
                              "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary\r\n"
                              "Content-Length: 500\r\n"
                              "Connection: keep-alive\r\n"
                              "\r\n";
    Request req;
    
    String src = { (char *)request_str, (int)strlen(request_str) };
    int ret = parse_request(src, &req);
    
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(req.num_headers, 4);
    
    TEST_PASSED;
    return 0;
}

// ============================================================================
// TEST RUNNER
// ============================================================================

int main(void) {
    int tests_run = 0;
    int tests_passed = 0;
    
    printf("\n=== BASIC GET REQUEST TESTS ===\n");
    if (test_simple_get_request() == 0) tests_passed++;
    tests_run++;
    if (test_get_with_query_string() == 0) tests_passed++;
    tests_run++;
    if (test_get_with_complex_query() == 0) tests_passed++;
    tests_run++;
    
    printf("\n=== POST REQUEST TESTS ===\n");
    if (test_simple_post_request() == 0) tests_passed++;
    tests_run++;
    if (test_post_with_content_type() == 0) tests_passed++;
    tests_run++;
    if (test_post_form_urlencoded() == 0) tests_passed++;
    tests_run++;
    
    printf("\n=== MULTIPLE HEADERS TESTS ===\n");
    if (test_multiple_headers() == 0) tests_passed++;
    tests_run++;
    if (test_many_headers() == 0) tests_passed++;
    tests_run++;
    if (test_max_headers_boundary() == 0) tests_passed++;
    tests_run++;
    
    printf("\n=== HEADER VALUE TESTS ===\n");
    if (test_header_with_spaces_in_value() == 0) tests_passed++;
    tests_run++;
    if (test_header_with_special_characters() == 0) tests_passed++;
    tests_run++;
    if (test_header_with_tabs() == 0) tests_passed++;
    tests_run++;
    
    printf("\n=== HTTP VERSION TESTS ===\n");
    if (test_http_version_1_0() == 0) tests_passed++;
    tests_run++;
    if (test_http_version_1_1() == 0) tests_passed++;
    tests_run++;
    if (test_http_version_2_0() == 0) tests_passed++;
    tests_run++;
    
    printf("\n=== OTHER HTTP METHODS TESTS ===\n");
    if (test_put_method() == 0) tests_passed++;
    tests_run++;
    if (test_delete_method() == 0) tests_passed++;
    tests_run++;
    if (test_patch_method() == 0) tests_passed++;
    tests_run++;
    if (test_options_method() == 0) tests_passed++;
    tests_run++;
    if (test_head_method() == 0) tests_passed++;
    tests_run++;
    
    printf("\n=== LARGE DATA TESTS ===\n");
    if (test_large_query_string() == 0) tests_passed++;
    tests_run++;
    if (test_large_header_value() == 0) tests_passed++;
    tests_run++;
    if (test_many_query_parameters() == 0) tests_passed++;
    tests_run++;
    
    printf("\n=== BORDER CASE / ERROR TESTS ===\n");
    if (test_missing_method() == 0) tests_passed++;
    tests_run++;
    if (test_missing_target() == 0) tests_passed++;
    tests_run++;
    if (test_missing_http_version() == 0) tests_passed++;
    tests_run++;
    if (test_invalid_http_version() == 0) tests_passed++;
    tests_run++;
    if (test_missing_header_colon() == 0) tests_passed++;
    tests_run++;
    if (test_missing_crlf_after_header() == 0) tests_passed++;
    tests_run++;
    if (test_empty_request() == 0) tests_passed++;
    tests_run++;
    if (test_only_method_no_space() == 0) tests_passed++;
    tests_run++;
    if (test_root_path() == 0) tests_passed++;
    tests_run++;
    if (test_deep_path() == 0) tests_passed++;
    tests_run++;
    if (test_path_with_special_characters() == 0) tests_passed++;
    tests_run++;
    if (test_single_header() == 0) tests_passed++;
    tests_run++;
    if (test_case_sensitive_method() == 0) tests_passed++;
    tests_run++;
    if (test_numeric_method() == 0) tests_passed++;
    tests_run++;
    if (test_asterisk_target() == 0) tests_passed++;
    tests_run++;
    
    printf("\n=== REAL-WORLD SCENARIOS ===\n");
    if (test_real_world_json_post() == 0) tests_passed++;
    tests_run++;
    if (test_real_world_browser_get() == 0) tests_passed++;
    tests_run++;
    if (test_real_world_file_upload_form() == 0) tests_passed++;
    tests_run++;
    
    printf("\n=== TEST SUMMARY ===\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_run - tests_passed);
    
    if (tests_passed == tests_run) {
        printf("✓ ALL TESTS PASSED\n\n");
        return 0;
    } else {
        printf("✗ SOME TESTS FAILED\n\n");
        return 1;
    }
}

