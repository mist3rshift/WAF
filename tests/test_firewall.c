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
// HELPER: Create regex rules file from config/rules.conf
// ============================================================================

void create_regex_rules_file(const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "[\n");
    
    /* SQLi avancé — obfuscation et bypass de filtre */
    fprintf(f, "  { \"id\": \"7001\", \"type\": 7, \"name\": \"Regex SQLi: OR/AND bypass with spaces/comments\", \"pattern\": \"(?i)(or|and)[\\\\s\\\\t/*]+[\\\\w'\\\\\\\"(]\", \"score\": 4 },\n");
    fprintf(f, "  { \"id\": \"7002\", \"type\": 7, \"name\": \"Regex SQLi: Union with optional whitespace\", \"pattern\": \"(?i)union[\\\\s/*]+select\", \"score\": 5 },\n");
    fprintf(f, "  { \"id\": \"7003\", \"type\": 7, \"name\": \"Regex SQLi: Inline comment obfuscation\", \"pattern\": \"/\\\\*[^*]*\\\\*/\", \"score\": 2 },\n");
    fprintf(f, "  { \"id\": \"7004\", \"type\": 7, \"name\": \"Regex SQLi: Tautology variants\", \"pattern\": \"(?i)'\\\\s*(or|and)\\\\s*'[^']*'\\\\s*=\\\\s*'\", \"score\": 5 },\n");
    fprintf(f, "  { \"id\": \"7005\", \"type\": 7, \"name\": \"Regex SQLi: Stacked queries\", \"pattern\": \";\\\\s*(select|insert|update|delete|drop|alter)\", \"score\": 5 },\n");
    fprintf(f, "  { \"id\": \"7006\", \"type\": 7, \"name\": \"Regex SQLi: URL-encoded quote\", \"pattern\": \"%%27\", \"score\": 3 },\n");
    fprintf(f, "  { \"id\": \"7007\", \"type\": 7, \"name\": \"Regex SQLi: Double URL-encoded quote\", \"pattern\": \"%%2527\", \"score\": 4 },\n");
    fprintf(f, "  { \"id\": \"7008\", \"type\": 7, \"name\": \"Regex SQLi: Null byte injection\", \"pattern\": \"%%00\", \"score\": 3 },\n");
    
    /* XSS avancé — bypass d encodage et événements dynamiques */
    fprintf(f, "  { \"id\": \"7009\", \"type\": 7, \"name\": \"Regex XSS: Script tag with attributes\", \"pattern\": \"(?i)<script[^>]*>\", \"score\": 5 },\n");
    fprintf(f, "  { \"id\": \"7010\", \"type\": 7, \"name\": \"Regex XSS: On* event handlers\", \"pattern\": \"(?i)\\\\bon\\\\w+\\\\s*=\", \"score\": 4 },\n");
    fprintf(f, "  { \"id\": \"7011\", \"type\": 7, \"name\": \"Regex XSS: Javascript URI variants\", \"pattern\": \"(?i)j[\\\\s]*a[\\\\s]*v[\\\\s]*a[\\\\s]*s[\\\\s]*c[\\\\s]*r[\\\\s]*i[\\\\s]*p[\\\\s]*t[\\\\s]*:\", \"score\": 5 },\n");
    fprintf(f, "  { \"id\": \"7012\", \"type\": 7, \"name\": \"Regex XSS: HTML entity encoded script\", \"pattern\": \"(?i)&#x?[0-9a-f]+;\", \"score\": 2 },\n");
    fprintf(f, "  { \"id\": \"7013\", \"type\": 7, \"name\": \"Regex XSS: URL-encoded XSS\", \"pattern\": \"(?i)%%3c%%73%%63%%72%%69%%70%%74\", \"score\": 5 },\n");
    fprintf(f, "  { \"id\": \"7014\", \"type\": 7, \"name\": \"Regex XSS: DOM sink innerHTML\", \"pattern\": \"(?i)\\\\.innerHTML\\\\s*=\", \"score\": 4 },\n");
    fprintf(f, "  { \"id\": \"7015\", \"type\": 7, \"name\": \"Regex XSS: DOM sink document.write\", \"pattern\": \"(?i)document\\\\.write\\\\s*\\\\(\", \"score\": 4 },\n");
    
    /* Path Traversal — encodages alternatifs */
    fprintf(f, "  { \"id\": \"7016\", \"type\": 7, \"name\": \"Regex Path: URL-encoded traversal\", \"pattern\": \"(\\\\.\\\\.|%%2e%%2e|%%252e%%252e)[/\\\\\\\\]\", \"score\": 5 },\n");
    fprintf(f, "  { \"id\": \"7017\", \"type\": 7, \"name\": \"Regex Path: Backslash traversal (Windows)\", \"pattern\": \"(\\\\.\\\\.|%%2e%%2e)\\\\\\\\\", \"score\": 5 },\n");
    fprintf(f, "  { \"id\": \"7018\", \"type\": 7, \"name\": \"Regex Path: Null byte path bypass\", \"pattern\": \"\\\\.php%%00\", \"score\": 5 },\n");
    fprintf(f, "  { \"id\": \"7019\", \"type\": 7, \"name\": \"Regex Path: Repeated slash bypass\", \"pattern\": \"/{2,}\", \"score\": 2 },\n");
    fprintf(f, "  { \"id\": \"7020\", \"type\": 7, \"name\": \"Regex Path: Absolute path in param\", \"pattern\": \"(?i)(file|php|expect|zip|data)://\", \"score\": 5 },\n");
    
    /* RCE — injection shell avancée */
    fprintf(f, "  { \"id\": \"7021\", \"type\": 7, \"name\": \"Regex RCE: Pipe to shell\", \"pattern\": \"[|&;`$]\\\\s*(bash|sh|cmd|powershell)\", \"score\": 5 },\n");
    fprintf(f, "  { \"id\": \"7022\", \"type\": 7, \"name\": \"Regex RCE: Command substitution\", \"pattern\": \"\\\\$\\\\([^)]+\\\\)\", \"score\": 4 },\n");
    fprintf(f, "  { \"id\": \"7023\", \"type\": 7, \"name\": \"Regex RCE: Reverse shell pattern\", \"pattern\": \"(?i)(bash|nc|python|perl|ruby).*[0-9]+\\\\.[0-9]+\\\\.[0-9]+\\\\.[0-9]+.*[0-9]{2,5}\", \"score\": 5 },\n");
    fprintf(f, "  { \"id\": \"7024\", \"type\": 7, \"name\": \"Regex RCE: IFS separator bypass\", \"pattern\": \"\\\\$IFS\", \"score\": 4 },\n");
    fprintf(f, "  { \"id\": \"7025\", \"type\": 7, \"name\": \"Regex RCE: Encoded pipe char\", \"pattern\": \"%%7c\", \"score\": 2 },\n");
    
    /* SSRF */
    fprintf(f, "  { \"id\": \"7026\", \"type\": 7, \"name\": \"Regex SSRF: Internal IP range 10.x\", \"pattern\": \"(?i)(https?|ftp)://10\\\\.[0-9]{1,3}\\\\.\", \"score\": 5 },\n");
    fprintf(f, "  { \"id\": \"7027\", \"type\": 7, \"name\": \"Regex SSRF: Internal IP range 192.168.x\", \"pattern\": \"(?i)(https?|ftp)://192\\\\.168\\\\.\", \"score\": 5 },\n");
    fprintf(f, "  { \"id\": \"7028\", \"type\": 7, \"name\": \"Regex SSRF: Localhost variants\", \"pattern\": \"(?i)(https?|ftp)://(localhost|127\\\\.0\\\\.0\\\\.1|0\\\\.0\\\\.0\\\\.0|::1)\", \"score\": 5 },\n");
    fprintf(f, "  { \"id\": \"7029\", \"type\": 7, \"name\": \"Regex SSRF: Cloud metadata AWS\", \"pattern\": \"169\\\\.254\\\\.169\\\\.254\", \"score\": 5 },\n");
    fprintf(f, "  { \"id\": \"7030\", \"type\": 7, \"name\": \"Regex SSRF: Cloud metadata GCP/Azure\", \"pattern\": \"metadata\\\\.google\\\\.internal|metadata\\\\.azure\\\\.com\", \"score\": 5 },\n");
    
    /* Open Redirect */
    fprintf(f, "  { \"id\": \"7031\", \"type\": 7, \"name\": \"Regex Redirect: External URL in redirect param\", \"pattern\": \"(?i)(redirect|url|next|return|goto|dest)=https?://(?![a-z0-9.-]*yourdomain\\\\.com)\", \"score\": 4 },\n");
    fprintf(f, "  { \"id\": \"7032\", \"type\": 7, \"name\": \"Regex Redirect: Protocol-relative URL\", \"pattern\": \"(?i)(redirect|url|next|return)=//[a-z0-9]\", \"score\": 4 },\n");
    
    /* XXE */
    fprintf(f, "  { \"id\": \"7033\", \"type\": 7, \"name\": \"Regex XXE: DOCTYPE declaration\", \"pattern\": \"(?i)<!doctype[^>]*\\\\[\", \"score\": 5 },\n");
    fprintf(f, "  { \"id\": \"7034\", \"type\": 7, \"name\": \"Regex XXE: ENTITY keyword\", \"pattern\": \"(?i)<!entity\\\\s+\", \"score\": 5 },\n");
    fprintf(f, "  { \"id\": \"7035\", \"type\": 7, \"name\": \"Regex XXE: SYSTEM identifier\", \"pattern\": \"(?i)system\\\\s+['\\\"]\", \"score\": 4 },\n");
    
    /* SSTI */
    fprintf(f, "  { \"id\": \"7036\", \"type\": 7, \"name\": \"Regex SSTI: Jinja2/Twig expression\", \"pattern\": \"\\\\{\\\\{[^}]+\\\\}\\\\}\", \"score\": 4 },\n");
    fprintf(f, "  { \"id\": \"7037\", \"type\": 7, \"name\": \"Regex SSTI: Server template injection\", \"pattern\": \"(?i)\\\\{%%[^%%]*%%\\\\}\", \"score\": 4 },\n");
    
    /* NoSQL/LDAP Injection */
    fprintf(f, "  { \"id\": \"7038\", \"type\": 7, \"name\": \"Regex NoSQL: MongoDB operator injection\", \"pattern\": \"(?i)\\\\$[a-z]+\", \"score\": 3 },\n");
    fprintf(f, "  { \"id\": \"7039\", \"type\": 7, \"name\": \"Regex LDAP: Filter injection\", \"pattern\": \"(?i)[*()&|]\", \"score\": 2 }\n");
    
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
    
    printf("\n=== REGEX RULES TESTS (Category 7) ===\n");
    
    // Load regex rules
    create_regex_rules_file("/tmp/regex_rules.conf");
    load_rules("/tmp/regex_rules.conf");
    
    // 7001: OR/AND bypass with spaces/comments
    WafEvent event_7001;
    memset(&event_7001, 0, sizeof(WafEvent));
    event_7001.threshold = 10;
    inspect_data("id OR  /* comment */ 1", "QUERY_STRING", &event_7001);
    if (event_7001.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7001 (OR/AND bypass): %s\n", event_7001.anomaly_score > 0 ? "✓" : "✗");
    
    // 7002: Union with optional whitespace
    WafEvent event_7002;
    memset(&event_7002, 0, sizeof(WafEvent));
    event_7002.threshold = 10;
    inspect_data("union  /**/  select", "QUERY_STRING", &event_7002);
    if (event_7002.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7002 (Union whitespace): %s\n", event_7002.anomaly_score > 0 ? "✓" : "✗");
    
    // 7003: Inline comment obfuscation
    WafEvent event_7003;
    memset(&event_7003, 0, sizeof(WafEvent));
    event_7003.threshold = 10;
    inspect_data("select /*+ */ * from users", "QUERY_STRING", &event_7003);
    if (event_7003.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7003 (Inline comments): %s\n", event_7003.anomaly_score > 0 ? "✓" : "✗");
    
    // 7004: Tautology variants
    WafEvent event_7004;
    memset(&event_7004, 0, sizeof(WafEvent));
    event_7004.threshold = 10;
    inspect_data("' or '1'='1", "QUERY_STRING", &event_7004);
    if (event_7004.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7004 (Tautology): %s\n", event_7004.anomaly_score > 0 ? "✓" : "✗");
    
    // 7005: Stacked queries
    WafEvent event_7005;
    memset(&event_7005, 0, sizeof(WafEvent));
    event_7005.threshold = 10;
    inspect_data("select 1; DROP TABLE users", "QUERY_STRING", &event_7005);
    if (event_7005.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7005 (Stacked queries): %s\n", event_7005.anomaly_score > 0 ? "✓" : "✗");
    
    // 7006: URL-encoded quote
    WafEvent event_7006;
    memset(&event_7006, 0, sizeof(WafEvent));
    event_7006.threshold = 10;
    inspect_data("id=%27", "QUERY_STRING", &event_7006);
    if (event_7006.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7006 (URL-encoded quote): %s\n", event_7006.anomaly_score > 0 ? "✓" : "✗");
    
    // 7007: Double URL-encoded quote
    WafEvent event_7007;
    memset(&event_7007, 0, sizeof(WafEvent));
    event_7007.threshold = 10;
    inspect_data("id=%2527", "QUERY_STRING", &event_7007);
    if (event_7007.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7007 (Double URL-encoded): %s\n", event_7007.anomaly_score > 0 ? "✓" : "✗");
    
    // 7008: Null byte injection
    WafEvent event_7008;
    memset(&event_7008, 0, sizeof(WafEvent));
    event_7008.threshold = 10;
    inspect_data("file%00", "QUERY_STRING", &event_7008);
    if (event_7008.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7008 (Null byte): %s\n", event_7008.anomaly_score > 0 ? "✓" : "✗");
    
    // 7009: Script tag with attributes
    WafEvent event_7009;
    memset(&event_7009, 0, sizeof(WafEvent));
    event_7009.threshold = 10;
    inspect_data("<script src='evil.js'>", "URI", &event_7009);
    if (event_7009.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7009 (Script tag): %s\n", event_7009.anomaly_score > 0 ? "✓" : "✗");
    
    // 7010: On* event handlers
    WafEvent event_7010;
    memset(&event_7010, 0, sizeof(WafEvent));
    event_7010.threshold = 10;
    inspect_data("onclick=alert(1)", "QUERY_STRING", &event_7010);
    if (event_7010.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7010 (Event handlers): %s\n", event_7010.anomaly_score > 0 ? "✓" : "✗");
    
    // 7011: Javascript URI variants
    WafEvent event_7011;
    memset(&event_7011, 0, sizeof(WafEvent));
    event_7011.threshold = 10;
    inspect_data("j a v a s c r i p t:", "QUERY_STRING", &event_7011);
    if (event_7011.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7011 (Javascript URI): %s\n", event_7011.anomaly_score > 0 ? "✓" : "✗");
    
    // 7012: HTML entity encoded script
    WafEvent event_7012;
    memset(&event_7012, 0, sizeof(WafEvent));
    event_7012.threshold = 10;
    inspect_data("&#97;&#108;&#101;", "QUERY_STRING", &event_7012);
    if (event_7012.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7012 (HTML entities): %s\n", event_7012.anomaly_score > 0 ? "✓" : "✗");
    
    // 7013: URL-encoded XSS
    WafEvent event_7013;
    memset(&event_7013, 0, sizeof(WafEvent));
    event_7013.threshold = 10;
    inspect_data("%3c%73%63%72%69%70%74", "QUERY_STRING", &event_7013);
    if (event_7013.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7013 (URL-encoded XSS): %s\n", event_7013.anomaly_score > 0 ? "✓" : "✗");
    
    // 7014: DOM sink innerHTML
    WafEvent event_7014;
    memset(&event_7014, 0, sizeof(WafEvent));
    event_7014.threshold = 10;
    inspect_data(".innerHTML = x", "QUERY_STRING", &event_7014);
    if (event_7014.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7014 (innerHTML): %s\n", event_7014.anomaly_score > 0 ? "✓" : "✗");
    
    // 7015: DOM sink document.write
    WafEvent event_7015;
    memset(&event_7015, 0, sizeof(WafEvent));
    event_7015.threshold = 10;
    inspect_data("document.write(", "QUERY_STRING", &event_7015);
    if (event_7015.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7015 (document.write): %s\n", event_7015.anomaly_score > 0 ? "✓" : "✗");
    
    // 7016: URL-encoded traversal
    WafEvent event_7016;
    memset(&event_7016, 0, sizeof(WafEvent));
    event_7016.threshold = 10;
    inspect_data("%2e%2e/", "URI", &event_7016);
    if (event_7016.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7016 (URL-encoded traversal): %s\n", event_7016.anomaly_score > 0 ? "✓" : "✗");
    
    // 7017: Backslash traversal (Windows)
    WafEvent event_7017;
    memset(&event_7017, 0, sizeof(WafEvent));
    event_7017.threshold = 10;
    inspect_data("..\\\\", "URI", &event_7017);
    if (event_7017.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7017 (Backslash traversal): %s\n", event_7017.anomaly_score > 0 ? "✓" : "✗");
    
    // 7018: Null byte path bypass
    WafEvent event_7018;
    memset(&event_7018, 0, sizeof(WafEvent));
    event_7018.threshold = 10;
    inspect_data(".php%00", "URI", &event_7018);
    if (event_7018.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7018 (Null byte path): %s\n", event_7018.anomaly_score > 0 ? "✓" : "✗");
    
    // 7019: Repeated slash bypass
    WafEvent event_7019;
    memset(&event_7019, 0, sizeof(WafEvent));
    event_7019.threshold = 10;
    inspect_data("///etc///passwd", "URI", &event_7019);
    if (event_7019.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7019 (Repeated slashes): %s\n", event_7019.anomaly_score > 0 ? "✓" : "✗");
    
    // 7020: Absolute path in param
    WafEvent event_7020;
    memset(&event_7020, 0, sizeof(WafEvent));
    event_7020.threshold = 10;
    inspect_data("file://etc/passwd", "QUERY_STRING", &event_7020);
    if (event_7020.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7020 (Protocol schemes): %s\n", event_7020.anomaly_score > 0 ? "✓" : "✗");
    
    // 7021: Pipe to shell
    WafEvent event_7021;
    memset(&event_7021, 0, sizeof(WafEvent));
    event_7021.threshold = 10;
    inspect_data("| bash", "QUERY_STRING", &event_7021);
    if (event_7021.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7021 (Pipe to shell): %s\n", event_7021.anomaly_score > 0 ? "✓" : "✗");
    
    // 7022: Command substitution
    WafEvent event_7022;
    memset(&event_7022, 0, sizeof(WafEvent));
    event_7022.threshold = 10;
    inspect_data("$(whoami)", "QUERY_STRING", &event_7022);
    if (event_7022.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7022 (Command substitution): %s\n", event_7022.anomaly_score > 0 ? "✓" : "✗");
    
    // 7023: Reverse shell pattern
    WafEvent event_7023;
    memset(&event_7023, 0, sizeof(WafEvent));
    event_7023.threshold = 10;
    inspect_data("bash 192.168.1.1 4444", "QUERY_STRING", &event_7023);
    if (event_7023.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7023 (Reverse shell): %s\n", event_7023.anomaly_score > 0 ? "✓" : "✗");
    
    // 7024: IFS separator bypass
    WafEvent event_7024;
    memset(&event_7024, 0, sizeof(WafEvent));
    event_7024.threshold = 10;
    inspect_data("$IFS", "QUERY_STRING", &event_7024);
    if (event_7024.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7024 (IFS separator): %s\n", event_7024.anomaly_score > 0 ? "✓" : "✗");
    
    // 7025: Encoded pipe char
    WafEvent event_7025;
    memset(&event_7025, 0, sizeof(WafEvent));
    event_7025.threshold = 10;
    inspect_data("%7c", "QUERY_STRING", &event_7025);
    if (event_7025.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7025 (Encoded pipe): %s\n", event_7025.anomaly_score > 0 ? "✓" : "✗");
    
    // 7026: Internal IP range 10.x
    WafEvent event_7026;
    memset(&event_7026, 0, sizeof(WafEvent));
    event_7026.threshold = 10;
    inspect_data("http://10.0.0.1", "QUERY_STRING", &event_7026);
    if (event_7026.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7026 (SSRF 10.x): %s\n", event_7026.anomaly_score > 0 ? "✓" : "✗");
    
    // 7027: Internal IP range 192.168.x
    WafEvent event_7027;
    memset(&event_7027, 0, sizeof(WafEvent));
    event_7027.threshold = 10;
    inspect_data("https://192.168.1.1", "QUERY_STRING", &event_7027);
    if (event_7027.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7027 (SSRF 192.168): %s\n", event_7027.anomaly_score > 0 ? "✓" : "✗");
    
    // 7028: Localhost variants
    WafEvent event_7028;
    memset(&event_7028, 0, sizeof(WafEvent));
    event_7028.threshold = 10;
    inspect_data("http://127.0.0.1", "QUERY_STRING", &event_7028);
    if (event_7028.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7028 (SSRF localhost): %s\n", event_7028.anomaly_score > 0 ? "✓" : "✗");
    
    // 7029: Cloud metadata AWS
    WafEvent event_7029;
    memset(&event_7029, 0, sizeof(WafEvent));
    event_7029.threshold = 10;
    inspect_data("http://169.254.169.254", "QUERY_STRING", &event_7029);
    if (event_7029.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7029 (AWS metadata): %s\n", event_7029.anomaly_score > 0 ? "✓" : "✗");
    
    // 7030: Cloud metadata GCP/Azure
    WafEvent event_7030;
    memset(&event_7030, 0, sizeof(WafEvent));
    event_7030.threshold = 10;
    inspect_data("metadata.google.internal", "QUERY_STRING", &event_7030);
    if (event_7030.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7030 (GCP/Azure metadata): %s\n", event_7030.anomaly_score > 0 ? "✓" : "✗");
    
    // 7031: External URL in redirect param
    WafEvent event_7031;
    memset(&event_7031, 0, sizeof(WafEvent));
    event_7031.threshold = 10;
    inspect_data("redirect=https://evil.com", "QUERY_STRING", &event_7031);
    if (event_7031.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7031 (Open redirect): %s\n", event_7031.anomaly_score > 0 ? "✓" : "✗");
    
    // 7032: Protocol-relative URL
    WafEvent event_7032;
    memset(&event_7032, 0, sizeof(WafEvent));
    event_7032.threshold = 10;
    inspect_data("next=//evil.com", "QUERY_STRING", &event_7032);
    if (event_7032.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7032 (Protocol-relative): %s\n", event_7032.anomaly_score > 0 ? "✓" : "✗");
    
    // 7033: DOCTYPE declaration
    WafEvent event_7033;
    memset(&event_7033, 0, sizeof(WafEvent));
    event_7033.threshold = 10;
    inspect_data("<!DOCTYPE [", "QUERY_STRING", &event_7033);
    if (event_7033.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7033 (XXE DOCTYPE): %s\n", event_7033.anomaly_score > 0 ? "✓" : "✗");
    
    // 7034: ENTITY keyword
    WafEvent event_7034;
    memset(&event_7034, 0, sizeof(WafEvent));
    event_7034.threshold = 10;
    inspect_data("<!ENTITY ", "QUERY_STRING", &event_7034);
    if (event_7034.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7034 (XXE ENTITY): %s\n", event_7034.anomaly_score > 0 ? "✓" : "✗");
    
    // 7035: SYSTEM identifier
    WafEvent event_7035;
    memset(&event_7035, 0, sizeof(WafEvent));
    event_7035.threshold = 10;
    inspect_data("SYSTEM \"file.dtd\"", "QUERY_STRING", &event_7035);
    if (event_7035.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7035 (XXE SYSTEM): %s\n", event_7035.anomaly_score > 0 ? "✓" : "✗");
    
    // 7036: Jinja2/Twig expression
    WafEvent event_7036;
    memset(&event_7036, 0, sizeof(WafEvent));
    event_7036.threshold = 10;
    inspect_data("{{7*7}}", "QUERY_STRING", &event_7036);
    if (event_7036.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7036 (SSTI Jinja2): %s\n", event_7036.anomaly_score > 0 ? "✓" : "✗");
    
    // 7037: Server template injection
    WafEvent event_7037;
    memset(&event_7037, 0, sizeof(WafEvent));
    event_7037.threshold = 10;
    inspect_data("{%if x%}", "QUERY_STRING", &event_7037);
    if (event_7037.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7037 (SSTI template): %s\n", event_7037.anomaly_score > 0 ? "✓" : "✗");
    
    // 7038: MongoDB operator injection
    WafEvent event_7038;
    memset(&event_7038, 0, sizeof(WafEvent));
    event_7038.threshold = 10;
    inspect_data("$gt", "QUERY_STRING", &event_7038);
    if (event_7038.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7038 (NoSQL $operator): %s\n", event_7038.anomaly_score > 0 ? "✓" : "✗");
    
    // 7039: LDAP Filter injection
    WafEvent event_7039;
    memset(&event_7039, 0, sizeof(WafEvent));
    event_7039.threshold = 10;
    inspect_data("*)(uid=*", "QUERY_STRING", &event_7039);
    if (event_7039.anomaly_score > 0) tests_passed++;
    tests_run++;
    printf("  7039 (LDAP filter): %s\n", event_7039.anomaly_score > 0 ? "✓" : "✗");
    
    free_rules();

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