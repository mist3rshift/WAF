#include "../inc/firewall.h"
#include "../inc/request_parser.h"
#include "../inc/internal_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <math.h>

#define TEST_PASSED printf("✓ %s passed\n", __func__)
#define TEST_FAILED printf("✗ %s FAILED\n", __func__); return 1
#define ASSERT_EQ(a, b) if ((a) != (b)) { printf("  Assertion failed: %d != %d\n", (int)(a), (int)(b)); TEST_FAILED; }
#define ASSERT_TRUE(cond) if (!(cond)) { printf("  Assertion failed: condition is false\n"); TEST_FAILED; }
#define ASSERT_FALSE(cond) if ((cond)) { printf("  Assertion failed: condition is true\n"); TEST_FAILED; }
#define ASSERT_STR_EQ(a, b) if (strcmp((a), (b)) != 0) { printf("  String mismatch: '%s' != '%s'\n", (a), (b)); TEST_FAILED; }
#define ASSERT_STR_CONTAINS(haystack, needle) if (strstr((haystack), (needle)) == NULL) { printf("  String not found: '%s' not in '%s'\n", (needle), (haystack)); TEST_FAILED; }

// ============================================================================
// HELPER FUNCTION: Create temporary test rules file
// ============================================================================

void create_test_rules_file(const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "[\n");
    fprintf(f, "  /* --- SQL INJECTION RULES --- */\n");
    fprintf(f, "  { \"id\": \"1001\", \"type\": 1, \"name\": \"SQLi: OR 1=1\", \"pattern\": \"or 1=1\", \"score\": 5 },\n");
    fprintf(f, "  { \"id\": \"1002\", \"type\": 1, \"name\": \"SQLi: Union Select\", \"pattern\": \"union select\", \"score\": 5 },\n");
    fprintf(f, "  { \"id\": \"1003\", \"type\": 1, \"name\": \"SQLi: Drop Table\", \"pattern\": \"drop table\", \"score\": 5 },\n");
    fprintf(f, "  { \"id\": \"1004\", \"type\": 1, \"name\": \"SQLi: Sleep\", \"pattern\": \"sleep(\", \"score\": 4 },\n");
    fprintf(f, "  { \"id\": \"1005\", \"type\": 1, \"name\": \"SQLi: Load File\", \"pattern\": \"load_file(\", \"score\": 5 },\n");
    fprintf(f, "  { \"id\": \"1006\", \"type\": 1, \"name\": \"SQLi: Order By\", \"pattern\": \"order by\", \"score\": 1 },\n");
    fprintf(f, "  { \"id\": \"1007\", \"type\": 1, \"name\": \"SQLi: Union\", \"pattern\": \"union\", \"score\": 3 },\n");
    fprintf(f, "  \n");
    fprintf(f, "  /* --- XSS RULES --- */\n");
    fprintf(f, "  { \"id\": \"2001\", \"type\": 2, \"name\": \"XSS: Script Tag\", \"pattern\": \"<script>\", \"score\": 5 },\n");
    fprintf(f, "  { \"id\": \"2002\", \"type\": 2, \"name\": \"XSS: Alert\", \"pattern\": \"alert(\", \"score\": 4 },\n");
    fprintf(f, "  { \"id\": \"2003\", \"type\": 2, \"name\": \"XSS: OnError\", \"pattern\": \"onerror=\", \"score\": 4 },\n");
    fprintf(f, "  { \"id\": \"2004\", \"type\": 2, \"name\": \"XSS: OnLoad\", \"pattern\": \"onload=\", \"score\": 4 },\n");
    fprintf(f, "  { \"id\": \"2005\", \"type\": 2, \"name\": \"XSS: Iframe\", \"pattern\": \"<iframe>\", \"score\": 4 },\n");
    fprintf(f, "  { \"id\": \"2006\", \"type\": 2, \"name\": \"XSS: Eval\", \"pattern\": \"eval(\", \"score\": 4 },\n");
    fprintf(f, "  \n");
    fprintf(f, "  /* --- PATH TRAVERSAL RULES --- */\n");
    fprintf(f, "  { \"id\": \"3001\", \"type\": 3, \"name\": \"Path: Dot-Dot-Slash\", \"pattern\": \"../\", \"score\": 5 },\n");
    fprintf(f, "  { \"id\": \"3002\", \"type\": 3, \"name\": \"Path: Passwd\", \"pattern\": \"/etc/passwd\", \"score\": 5 },\n");
    fprintf(f, "  { \"id\": \"3003\", \"type\": 3, \"name\": \"Path: Shadow\", \"pattern\": \"/etc/shadow\", \"score\": 5 }\n");
    fprintf(f, "]\n");
    fclose(f);
}

// ============================================================================
// RULE LOADING TESTS
// ============================================================================

int test_load_rules_from_file() {
    create_test_rules_file("/tmp/test_rules.conf");
    
    int count = load_rules("/tmp/test_rules.conf");
    ASSERT_EQ(count, 16);
    ASSERT_EQ(get_rules_count(), 16);
    
    free_rules();
    TEST_PASSED;
    return 0;
}

int test_load_rules_file_not_found() {
    int count = load_rules("/tmp/nonexistent_rules_file_xyz.conf");
    ASSERT_EQ(count, -1);
    
    TEST_PASSED;
    return 0;
}

int test_load_rules_null_path() {
    int count = load_rules(NULL);
    ASSERT_EQ(count, -1);
    
    TEST_PASSED;
    return 0;
}

int test_load_rules_empty_file() {
    FILE *f = fopen("/tmp/empty_rules.conf", "w");
    fclose(f);
    
    int count = load_rules("/tmp/empty_rules.conf");
    ASSERT_EQ(count, -1);
    
    free_rules();
    TEST_PASSED;
    return 0;
}

int test_load_rules_invalid_json() {
    FILE *f = fopen("/tmp/invalid_rules.conf", "w");
    fprintf(f, "this is not json at all {{{");
    fclose(f);
    
    int count = load_rules("/tmp/invalid_rules.conf");
    ASSERT_EQ(count, -1);
    
    free_rules();
    TEST_PASSED;
    return 0;
}

int test_load_rules_with_comments() {
    FILE *f = fopen("/tmp/rules_with_comments.conf", "w");
    fprintf(f, "[\n");
    fprintf(f, "  /* This is a comment */\n");
    fprintf(f, "  { \"id\": \"1001\", \"type\": 1, \"name\": \"SQLi Test\", \"pattern\": \"or 1=1\", \"score\": 5 },\n");
    fprintf(f, "  /* Another comment block\n");
    fprintf(f, "     spanning multiple lines */\n");
    fprintf(f, "  { \"id\": \"2001\", \"type\": 2, \"name\": \"XSS Test\", \"pattern\": \"<script>\", \"score\": 5 }\n");
    fprintf(f, "]\n");
    fclose(f);
    
    int count = load_rules("/tmp/rules_with_comments.conf");
    ASSERT_EQ(count, 2);
    
    free_rules();
    TEST_PASSED;
    return 0;
}

// ============================================================================
// RULE RETRIEVAL TESTS
// ============================================================================

int test_get_rule_by_index() {
    create_test_rules_file("/tmp/test_rules.conf");
    load_rules("/tmp/test_rules.conf");
    
    rule *r = get_rule(0);
    ASSERT_TRUE(r != NULL);
    ASSERT_STR_EQ(r->id, "1001");
    ASSERT_EQ(r->type, 1);
    ASSERT_EQ(r->score, 5);
    ASSERT_STR_CONTAINS(r->pattern, "or 1=1");
    
    free_rules();
    TEST_PASSED;
    return 0;
}

int test_get_rule_out_of_bounds() {
    create_test_rules_file("/tmp/test_rules.conf");
    load_rules("/tmp/test_rules.conf");
    
    rule *r = get_rule(999);
    ASSERT_FALSE(r != NULL);
    
    r = get_rule(-1);
    ASSERT_FALSE(r != NULL);
    
    free_rules();
    TEST_PASSED;
    return 0;
}

int test_get_rule_by_id() {
    create_test_rules_file("/tmp/test_rules.conf");
    load_rules("/tmp/test_rules.conf");
    
    rule *r = get_rule_by_id("1001");
    ASSERT_TRUE(r != NULL);
    ASSERT_STR_EQ(r->id, "1001");
    ASSERT_EQ(r->type, 1);
    
    r = get_rule_by_id("2005");
    ASSERT_TRUE(r != NULL);
    ASSERT_STR_EQ(r->id, "2005");
    ASSERT_EQ(r->type, 2);
    
    free_rules();
    TEST_PASSED;
    return 0;
}

int test_get_rule_by_id_not_found() {
    create_test_rules_file("/tmp/test_rules.conf");
    load_rules("/tmp/test_rules.conf");
    
    rule *r = get_rule_by_id("9999");
    ASSERT_FALSE(r != NULL);
    
    free_rules();
    TEST_PASSED;
    return 0;
}

int test_get_rule_by_id_null() {
    create_test_rules_file("/tmp/test_rules.conf");
    load_rules("/tmp/test_rules.conf");
    
    rule *r = get_rule_by_id(NULL);
    ASSERT_FALSE(r != NULL);
    
    free_rules();
    TEST_PASSED;
    return 0;
}

// ============================================================================
// URL DECODING TESTS
// ============================================================================

int test_url_decode_simple() {
    char buf[256] = "hello%20world";
    url_decode_inplace(buf);
    ASSERT_STR_EQ(buf, "hello world");
    
    TEST_PASSED;
    return 0;
}

int test_url_decode_multiple_escapes() {
    char buf[256] = "id%3D123%26name%3DJohn";
    url_decode_inplace(buf);
    ASSERT_STR_EQ(buf, "id=123&name=John");
    
    TEST_PASSED;
    return 0;
}

int test_url_decode_plus_sign() {
    char buf[256] = "hello+world+test";
    url_decode_inplace(buf);
    ASSERT_STR_EQ(buf, "hello world test");
    
    TEST_PASSED;
    return 0;
}

int test_url_decode_hex_values() {
    char buf[256] = "%27OR%271%27%3D%271";
    url_decode_inplace(buf);
    ASSERT_STR_EQ(buf, "'OR'1'='1");
    
    TEST_PASSED;
    return 0;
}

int test_url_decode_empty_string() {
    char buf[256] = "";
    url_decode_inplace(buf);
    ASSERT_STR_EQ(buf, "");
    
    TEST_PASSED;
    return 0;
}

int test_url_decode_no_encoding() {
    char buf[256] = "plaintext";
    url_decode_inplace(buf);
    ASSERT_STR_EQ(buf, "plaintext");
    
    TEST_PASSED;
    return 0;
}

// ============================================================================
// NORMALIZE_TARGET TESTS
// ============================================================================

int test_normalize_target_uppercase() {
    char dest[256];
    normalize_target(dest, "HELLO WORLD", sizeof(dest));
    // Check that the result starts with the expected value
    ASSERT_TRUE(strncmp(dest, "hello world", 11) == 0);
    
    TEST_PASSED;
    return 0;
}

int test_normalize_target_mixed_case() {
    char dest[256];
    normalize_target(dest, "OrDeR bY", sizeof(dest));
    // Check that the result starts with the expected value
    ASSERT_TRUE(strncmp(dest, "order by", 8) == 0);
    
    TEST_PASSED;
    return 0;
}

int test_normalize_target_already_lowercase() {
    char dest[256];
    normalize_target(dest, "union select", sizeof(dest));
    // Check that the result starts with the expected value
    ASSERT_TRUE(strncmp(dest, "union select", 12) == 0);
    
    TEST_PASSED;
    return 0;
}

int test_normalize_target_truncation() {
    char dest[5];
    normalize_target(dest, "hello world", sizeof(dest));
    ASSERT_EQ(strlen(dest), 4);
    
    TEST_PASSED;
    return 0;
}

// ============================================================================
// EXTRACT SECURITY CONTEXT TESTS
// ============================================================================

int test_extract_security_context_simple_get() {
    Request raw_req;
    raw_req.method = S("GET");
    raw_req.target = S("/api/users");
    raw_req.minor = 1.1;
    raw_req.num_headers = 1;
    raw_req.headers[0].name = S("Host");
    raw_req.headers[0].value = S("example.com");
    
    RequestInfo waf_req;
    extract_security_context(&raw_req, &waf_req);
    
    ASSERT_STR_EQ(waf_req.method, "GET");
    ASSERT_STR_EQ(waf_req.uri, "/api/users");
    ASSERT_STR_EQ(waf_req.protocol, "HTTP/1.1");
    ASSERT_STR_EQ(waf_req.host, "example.com");
    
    TEST_PASSED;
    return 0;
}

int test_extract_security_context_with_query_string() {
    Request raw_req;
    raw_req.method = S("GET");
    raw_req.target = S("/search?q=test&id=123");
    raw_req.minor = 1.1;
    raw_req.num_headers = 2;
    raw_req.headers[0].name = S("Host");
    raw_req.headers[0].value = S("example.com");
    raw_req.headers[1].name = S("User-Agent");
    raw_req.headers[1].value = S("Mozilla/5.0");
    
    RequestInfo waf_req;
    extract_security_context(&raw_req, &waf_req);
    
    ASSERT_STR_EQ(waf_req.method, "GET");
    ASSERT_STR_EQ(waf_req.uri, "/search");
    ASSERT_STR_EQ(waf_req.query_string, "q=test&id=123");
    ASSERT_STR_EQ(waf_req.host, "example.com");
    ASSERT_STR_EQ(waf_req.user_agent, "Mozilla/5.0");
    
    TEST_PASSED;
    return 0;
}

int test_extract_security_context_url_decoded() {
    Request raw_req;
    raw_req.method = S("GET");
    raw_req.target = S("/search?q=%27OR%271%27%3D%271");
    raw_req.minor = 1.1;
    raw_req.num_headers = 1;
    raw_req.headers[0].name = S("Host");
    raw_req.headers[0].value = S("example.com");
    
    RequestInfo waf_req;
    extract_security_context(&raw_req, &waf_req);
    
    ASSERT_STR_CONTAINS(waf_req.query_string, "'OR'1'=");
    
    TEST_PASSED;
    return 0;
}

int test_extract_security_context_content_length() {
    Request raw_req;
    raw_req.method = S("POST");
    raw_req.target = S("/api/data");
    raw_req.minor = 1.1;
    raw_req.num_headers = 2;
    raw_req.headers[0].name = S("Host");
    raw_req.headers[0].value = S("example.com");
    raw_req.headers[1].name = S("Content-Length");
    raw_req.headers[1].value = S("256");
    
    RequestInfo waf_req;
    extract_security_context(&raw_req, &waf_req);
    
    ASSERT_EQ(waf_req.content_length, 256);
    
    TEST_PASSED;
    return 0;
}

// ============================================================================
// INSPECT_DATA TESTS
// ============================================================================

int test_inspect_data_sqli_detected() {
    create_test_rules_file("/tmp/test_rules.conf");
    load_rules("/tmp/test_rules.conf");
    
    WafEvent event;
    memset(&event, 0, sizeof(WafEvent));
    event.threshold = 10;
    
    inspect_data("id OR 1=1", "QUERY_STRING", &event);
    
    ASSERT_TRUE(event.anomaly_score > 0);
    ASSERT_STR_EQ(event.rule.id, "1001");
    
    free_rules();
    TEST_PASSED;
    return 0;
}

int test_inspect_data_xss_detected() {
    create_test_rules_file("/tmp/test_rules.conf");
    load_rules("/tmp/test_rules.conf");
    
    WafEvent event;
    memset(&event, 0, sizeof(WafEvent));
    event.threshold = 10;
    
    inspect_data("<script>alert('xss')</script>", "URI", &event);
    
    ASSERT_TRUE(event.anomaly_score > 0);
    ASSERT_STR_EQ(event.rule.id, "2001");
    
    free_rules();
    TEST_PASSED;
    return 0;
}

int test_inspect_data_multiple_matches() {
    create_test_rules_file("/tmp/test_rules.conf");
    load_rules("/tmp/test_rules.conf");
    
    WafEvent event;
    memset(&event, 0, sizeof(WafEvent));
    event.threshold = 10;
    
    inspect_data("id UNION SELECT 1 FROM users ORDER BY", "QUERY_STRING", &event);
    
    ASSERT_TRUE(event.anomaly_score > 5);
    
    free_rules();
    TEST_PASSED;
    return 0;
}

int test_inspect_data_case_insensitive() {
    create_test_rules_file("/tmp/test_rules.conf");
    load_rules("/tmp/test_rules.conf");
    
    WafEvent event;
    memset(&event, 0, sizeof(WafEvent));
    event.threshold = 10;
    
    inspect_data("id OR 1=1", "QUERY_STRING", &event);
    int score_lower = event.anomaly_score;
    
    memset(&event, 0, sizeof(WafEvent));
    inspect_data("ID OR 1=1", "QUERY_STRING", &event);
    int score_upper = event.anomaly_score;
    
    ASSERT_EQ(score_lower, score_upper);
    
    free_rules();
    TEST_PASSED;
    return 0;
}

int test_inspect_data_empty_string() {
    create_test_rules_file("/tmp/test_rules.conf");
    load_rules("/tmp/test_rules.conf");
    
    WafEvent event;
    memset(&event, 0, sizeof(WafEvent));
    event.threshold = 10;
    
    inspect_data("", "QUERY_STRING", &event);
    
    ASSERT_EQ(event.anomaly_score, 0);
    
    free_rules();
    TEST_PASSED;
    return 0;
}

int test_inspect_data_no_matches() {
    create_test_rules_file("/tmp/test_rules.conf");
    load_rules("/tmp/test_rules.conf");
    
    WafEvent event;
    memset(&event, 0, sizeof(WafEvent));
    event.threshold = 10;
    
    inspect_data("normal query parameter", "QUERY_STRING", &event);
    
    ASSERT_EQ(event.anomaly_score, 0);
    
    free_rules();
    TEST_PASSED;
    return 0;
}

// ============================================================================
// PERFORM_WAF_ANALYSIS TESTS
// ============================================================================

int test_perform_waf_analysis_clean_request() {
    create_test_rules_file("/tmp/test_rules.conf");
    load_rules("/tmp/test_rules.conf");
    
    Request raw_req;
    raw_req.method = S("GET");
    raw_req.target = S("/api/users/123");
    raw_req.minor = 1.1;
    raw_req.num_headers = 1;
    raw_req.headers[0].name = S("Host");
    raw_req.headers[0].value = S("example.com");
    
    WafEvent event;
    memset(&event, 0, sizeof(WafEvent));
    event.threshold = 50;
    
    int result = perform_waf_analysis(&raw_req, &event);
    
    ASSERT_EQ(result, 0);
    ASSERT_EQ(event.anomaly_score, 0);
    ASSERT_EQ(event.status_code, 200);
    
    free_rules();
    TEST_PASSED;
    return 0;
}

int test_perform_waf_analysis_sqli_under_threshold() {
    create_test_rules_file("/tmp/test_rules.conf");
    load_rules("/tmp/test_rules.conf");
    
    Request raw_req;
    raw_req.method = S("GET");
    raw_req.target = S("/search?q=order+by");
    raw_req.minor = 1.1;
    raw_req.num_headers = 1;
    raw_req.headers[0].name = S("Host");
    raw_req.headers[0].value = S("example.com");
    
    WafEvent event;
    memset(&event, 0, sizeof(WafEvent));
    event.threshold = 50;
    
    int result = perform_waf_analysis(&raw_req, &event);
    
    ASSERT_EQ(result, 0);
    ASSERT_TRUE(event.anomaly_score >= 0 && event.anomaly_score < 50);
    ASSERT_EQ(event.status_code, 200);
    
    free_rules();
    TEST_PASSED;
    return 0;
}

int test_perform_waf_analysis_sqli_over_threshold() {
    create_test_rules_file("/tmp/test_rules.conf");
    load_rules("/tmp/test_rules.conf");
    
    Request raw_req;
    raw_req.method = S("GET");
    raw_req.target = S("/search?q=or+1=1");
    raw_req.minor = 1.1;
    raw_req.num_headers = 1;
    raw_req.headers[0].name = S("Host");
    raw_req.headers[0].value = S("example.com");
    
    WafEvent event;
    memset(&event, 0, sizeof(WafEvent));
    event.threshold = 3;
    
    int result = perform_waf_analysis(&raw_req, &event);
    
    ASSERT_TRUE(event.anomaly_score >= 3);
    ASSERT_EQ(event.status_code, 403);
    
    free_rules();
    TEST_PASSED;
    return 0;
}

int test_perform_waf_analysis_xss_attack() {
    create_test_rules_file("/tmp/test_rules.conf");
    load_rules("/tmp/test_rules.conf");
    
    Request raw_req;
    raw_req.method = S("GET");
    raw_req.target = S("/page?content=%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E");
    raw_req.minor = 1.1;
    raw_req.num_headers = 1;
    raw_req.headers[0].name = S("Host");
    raw_req.headers[0].value = S("example.com");
    
    WafEvent event;
    memset(&event, 0, sizeof(WafEvent));
    event.threshold = 3;
    
    int result = perform_waf_analysis(&raw_req, &event);
    
    ASSERT_TRUE(event.anomaly_score >= 3);
    ASSERT_EQ(event.status_code, 403);
    
    free_rules();
    TEST_PASSED;
    return 0;
}

int test_perform_waf_analysis_path_traversal() {
    create_test_rules_file("/tmp/test_rules.conf");
    load_rules("/tmp/test_rules.conf");
    
    Request raw_req;
    raw_req.method = S("GET");
    raw_req.target = S("/%2E%2E/%2E%2E/%2E%2E/etc/passwd");
    raw_req.minor = 1.1;
    raw_req.num_headers = 1;
    raw_req.headers[0].name = S("Host");
    raw_req.headers[0].value = S("example.com");
    
    WafEvent event;
    memset(&event, 0, sizeof(WafEvent));
    event.threshold = 3;
    
    int result = perform_waf_analysis(&raw_req, &event);
    
    ASSERT_TRUE(event.anomaly_score >= 3);
    ASSERT_EQ(event.status_code, 403);
    
    free_rules();
    TEST_PASSED;
    return 0;
}

// ============================================================================
// BORDER CASES / EDGE CASES
// ============================================================================

int test_large_query_string() {
    create_test_rules_file("/tmp/test_rules.conf");
    load_rules("/tmp/test_rules.conf");
    
    char large_query[2048];
    strcpy(large_query, "/search?q=");
    for (int i = 0; i < 100; i++) {
        strcat(large_query, "a");
    }
    
    Request raw_req;
    raw_req.method = S("GET");
    raw_req.target.ptr = large_query;
    raw_req.target.len = (int)strlen(large_query);
    raw_req.minor = 1.1;
    raw_req.num_headers = 1;
    raw_req.headers[0].name = S("Host");
    raw_req.headers[0].value = S("example.com");
    
    WafEvent event;
    memset(&event, 0, sizeof(WafEvent));
    event.threshold = 50;
    
    int result = perform_waf_analysis(&raw_req, &event);
    ASSERT_EQ(result, 0);
    
    free_rules();
    TEST_PASSED;
    return 0;
}

int test_many_headers() {
    create_test_rules_file("/tmp/test_rules.conf");
    load_rules("/tmp/test_rules.conf");
    
    Request raw_req;
    raw_req.method = S("GET");
    raw_req.target = S("/api/data");
    raw_req.minor = 1.1;
    raw_req.num_headers = 5;
    raw_req.headers[0].name = S("Host");
    raw_req.headers[0].value = S("example.com");
    raw_req.headers[1].name = S("User-Agent");
    raw_req.headers[1].value = S("Mozilla/5.0");
    raw_req.headers[2].name = S("Accept");
    raw_req.headers[2].value = S("text/html");
    raw_req.headers[3].name = S("Content-Type");
    raw_req.headers[3].value = S("application/json");
    raw_req.headers[4].name = S("Content-Length");
    raw_req.headers[4].value = S("1024");
    
    WafEvent event;
    memset(&event, 0, sizeof(WafEvent));
    event.threshold = 50;
    
    int result = perform_waf_analysis(&raw_req, &event);
    ASSERT_EQ(result, 0);
    
    free_rules();
    TEST_PASSED;
    return 0;
}

int test_rule_with_max_score() {
    FILE *f = fopen("/tmp/max_score_rules.conf", "w");
    fprintf(f, "[\n");
    fprintf(f, "  { \"id\": \"1001\", \"type\": 1, \"name\": \"Test\", \"pattern\": \"test\", \"score\": 100 }\n");
    fprintf(f, "]\n");
    fclose(f);
    
    load_rules("/tmp/max_score_rules.conf");
    
    WafEvent event;
    memset(&event, 0, sizeof(WafEvent));
    event.threshold = 50;
    
    inspect_data("test", "URI", &event);
    
    ASSERT_EQ(event.anomaly_score, 100);
    
    free_rules();
    TEST_PASSED;
    return 0;
}

int test_special_characters_in_pattern() {
    FILE *f = fopen("/tmp/special_chars_rules.conf", "w");
    fprintf(f, "[\n");
    fprintf(f, "  { \"id\": \"1001\", \"type\": 1, \"name\": \"Special\", \"pattern\": \"||\" , \"score\": 3 }\n");
    fprintf(f, "]\n");
    fclose(f);
    
    load_rules("/tmp/special_chars_rules.conf");
    
    WafEvent event;
    memset(&event, 0, sizeof(WafEvent));
    event.threshold = 10;
    
    inspect_data("value1 || value2", "QUERY_STRING", &event);
    
    ASSERT_EQ(event.anomaly_score, 3);
    
    free_rules();
    TEST_PASSED;
    return 0;
}

int test_unicode_in_payload() {
    create_test_rules_file("/tmp/test_rules.conf");
    load_rules("/tmp/test_rules.conf");
    
    Request raw_req;
    raw_req.method = S("GET");
    raw_req.target = S("/search?q=café");
    raw_req.minor = 1.1;
    raw_req.num_headers = 1;
    raw_req.headers[0].name = S("Host");
    raw_req.headers[0].value = S("example.com");
    
    WafEvent event;
    memset(&event, 0, sizeof(WafEvent));
    event.threshold = 50;
    
    int result = perform_waf_analysis(&raw_req, &event);
    ASSERT_EQ(result, 0);
    
    free_rules();
    TEST_PASSED;
    return 0;
}

int test_null_pointer_handling() {
    WafEvent event;
    memset(&event, 0, sizeof(WafEvent));
    
    extract_security_context(NULL, &event.req);
    extract_security_context(NULL, NULL);
    inspect_data(NULL, "URI", &event);
    
    TEST_PASSED;
    return 0;
}

// ============================================================================
// TEST RUNNER
// ============================================================================

int main(void) {
    int tests_run = 0;
    int tests_passed = 0;
    
    printf("\n=== RULE LOADING TESTS ===\n");
    if (test_load_rules_from_file() == 0) tests_passed++;
    tests_run++;
    if (test_load_rules_file_not_found() == 0) tests_passed++;
    tests_run++;
    if (test_load_rules_null_path() == 0) tests_passed++;
    tests_run++;
    if (test_load_rules_empty_file() == 0) tests_passed++;
    tests_run++;
    if (test_load_rules_invalid_json() == 0) tests_passed++;
    tests_run++;
    if (test_load_rules_with_comments() == 0) tests_passed++;
    tests_run++;
    
    printf("\n=== RULE RETRIEVAL TESTS ===\n");
    if (test_get_rule_by_index() == 0) tests_passed++;
    tests_run++;
    if (test_get_rule_out_of_bounds() == 0) tests_passed++;
    tests_run++;
    if (test_get_rule_by_id() == 0) tests_passed++;
    tests_run++;
    if (test_get_rule_by_id_not_found() == 0) tests_passed++;
    tests_run++;
    if (test_get_rule_by_id_null() == 0) tests_passed++;
    tests_run++;
    
    printf("\n=== URL DECODING TESTS ===\n");
    if (test_url_decode_simple() == 0) tests_passed++;
    tests_run++;
    if (test_url_decode_multiple_escapes() == 0) tests_passed++;
    tests_run++;
    if (test_url_decode_plus_sign() == 0) tests_passed++;
    tests_run++;
    if (test_url_decode_hex_values() == 0) tests_passed++;
    tests_run++;
    if (test_url_decode_empty_string() == 0) tests_passed++;
    tests_run++;
    if (test_url_decode_no_encoding() == 0) tests_passed++;
    tests_run++;
    
    printf("\n=== NORMALIZE_TARGET TESTS ===\n");
    if (test_normalize_target_uppercase() == 0) tests_passed++;
    tests_run++;
    if (test_normalize_target_mixed_case() == 0) tests_passed++;
    tests_run++;
    if (test_normalize_target_already_lowercase() == 0) tests_passed++;
    tests_run++;
    if (test_normalize_target_truncation() == 0) tests_passed++;
    tests_run++;

    printf("\n=== EXTRACT SECURITY CONTEXT TESTS ===\n");
    if (test_extract_security_context_simple_get() == 0) tests_passed++;
    tests_run++;
    if (test_extract_security_context_with_query_string() == 0) tests_passed++;
    tests_run++;
    if (test_extract_security_context_url_decoded() == 0) tests_passed++;
    tests_run++;
    if (test_extract_security_context_content_length() == 0) tests_passed++;
    tests_run++;
    
    printf("\n=== INSPECT_DATA TESTS ===\n");
    if (test_inspect_data_sqli_detected() == 0) tests_passed++;
    tests_run++;
    if (test_inspect_data_xss_detected() == 0) tests_passed++;
    tests_run++;
    if (test_inspect_data_multiple_matches() == 0) tests_passed++;
    tests_run++;
    if (test_inspect_data_case_insensitive() == 0) tests_passed++;
    tests_run++;
    if (test_inspect_data_empty_string() == 0) tests_passed++;
    tests_run++;
    if (test_inspect_data_no_matches() == 0) tests_passed++;
    tests_run++;
    
    printf("\n=== PERFORM_WAF_ANALYSIS TESTS ===\n");
    if (test_perform_waf_analysis_clean_request() == 0) tests_passed++;
    tests_run++;
    if (test_perform_waf_analysis_sqli_under_threshold() == 0) tests_passed++;
    tests_run++;
    if (test_perform_waf_analysis_sqli_over_threshold() == 0) tests_passed++;
    tests_run++;
    if (test_perform_waf_analysis_xss_attack() == 0) tests_passed++;
    tests_run++;
    if (test_perform_waf_analysis_path_traversal() == 0) tests_passed++;
    tests_run++;
    
    printf("\n=== BORDER CASES / EDGE CASES ===\n");
    if (test_large_query_string() == 0) tests_passed++;
    tests_run++;
    if (test_many_headers() == 0) tests_passed++;
    tests_run++;
    if (test_rule_with_max_score() == 0) tests_passed++;
    tests_run++;
    if (test_special_characters_in_pattern() == 0) tests_passed++;
    tests_run++;
    if (test_unicode_in_payload() == 0) tests_passed++;
    tests_run++;
    if (test_null_pointer_handling() == 0) tests_passed++;
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