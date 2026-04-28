#include "../inc/firewall.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

// Forward declaration for load_rules function
int load_rules(char* rules_config_path);
int get_rules_count(void);
void free_rules(void);
typedef struct _rule rule;  // Forward declaration
rule* get_rule(int index);
rule* get_rule_by_id(const char* rule_id);

/**
 * Test: load_rules with valid configuration file
 */
void test_load_rules_valid_config() {
    printf("\n=== Test: load_rules with valid config ===\n");
    
    int result = load_rules("../config/rules.conf");
    
    printf("Loaded rules count: %d\n", result);
    assert(result > 0);
    
    // New config has 95 rules total
    if (result >= 90) {
        printf("✓ Rules count is optimal: %d\n", result);
    }
    
    // Verify rules were loaded correctly
    int count = get_rules_count();
    assert(count == result);
    printf("Rules count verified: %d\n", count);
    
    // Check SQL Injection rule (1001)
    rule* r1 = get_rule(0);
    assert(r1 != NULL);
    assert(strcmp(r1->id, "1001") == 0);
    assert(r1->type == 1);
    assert(r1->score == 5);
    printf("Rule 1001 verified: %s (type=%d, score=%d)\n", r1->id, r1->type, r1->score);
    
    // Check XSS rule by ID lookup
    rule* r_xss = get_rule_by_id("2001");
    assert(r_xss != NULL);
    assert(r_xss->type == 2);
    assert(r_xss->score == 5);
    printf("Rule 2001 verified: %s (type=%d, score=%d)\n", r_xss->id, r_xss->type, r_xss->score);
    
    // Check Path Traversal rule
    rule* r_path = get_rule_by_id("3001");
    assert(r_path != NULL);
    assert(r_path->type == 3);
    assert(r_path->score == 5);
    printf("Rule 3001 verified: %s (type=%d, score=%d)\n", r_path->id, r_path->type, r_path->score);
    
    // Check RCE rule
    rule* r_rce = get_rule_by_id("4001");
    assert(r_rce != NULL);
    assert(r_rce->type == 4);
    assert(r_rce->score == 5);
    printf("Rule 4001 verified: %s (type=%d, score=%d)\n", r_rce->id, r_rce->type, r_rce->score);
    
    // Check Bot rule
    rule* r_bot = get_rule_by_id("5001");
    assert(r_bot != NULL);
    assert(r_bot->type == 5);
    assert(r_bot->score == 5);
    printf("Rule 5001 verified: %s (type=%d, score=%d)\n", r_bot->id, r_bot->type, r_bot->score);
    
    printf("✓ Valid config test passed\n");
}

/**
 * Test: load_rules with NULL path
 */
void test_load_rules_null_path() {
    printf("\n=== Test: load_rules with NULL path ===\n");
    
    int result = load_rules(NULL);
    
    printf("Result: %d\n", result);
    assert(result == -1);
    
    printf("✓ NULL path test passed\n");
}

/**
 * Test: load_rules with non-existent file
 */
void test_load_rules_nonexistent_file() {
    printf("\n=== Test: load_rules with non-existent file ===\n");
    
    int result = load_rules("./config/nonexistent_rules.conf");
    
    printf("Result: %d\n", result);
    assert(result == -1);
    
    printf("✓ Non-existent file test passed\n");
}

/**
 * Test: free_rules properly deallocates memory
 */
void test_free_rules() {
    printf("\n=== Test: free_rules memory deallocation ===\n");
    
    // Load rules
    int result = load_rules("../config/rules.conf");
    assert(result > 0);
    printf("Rules loaded: %d\n", result);
    
    int count_before = get_rules_count();
    printf("Rules count before free: %d\n", count_before);
    
    // Free rules
    free_rules();
    printf("Rules freed\n");
    
    // Verify rules are cleared
    int count_after = get_rules_count();
    assert(count_after == 0);
    printf("Rules count after free: %d\n", count_after);
    
    // Verify getting rules returns NULL after free
    rule* r = get_rule(0);
    assert(r == NULL);
    printf("Getting rules after free returns NULL: ✓\n");
    
    printf("✓ Free rules test passed\n");
}


int main() {
    printf("========== Firewall Tests ==========\n");
    
    // Run all tests
    test_load_rules_null_path();
    test_load_rules_nonexistent_file();
    test_load_rules_valid_config();
    test_free_rules();
    
    printf("\n========== All tests completed successfully ==========\n");
    
    return 0;
}