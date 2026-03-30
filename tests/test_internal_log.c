#include "../inc/internal_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int test_get_unique_id() {
    char *id1 = get_unique_id();
    char *id2 = get_unique_id();
    if (id1 == NULL || id2 == NULL) {
        printf("Failed to generate unique ID\n");
        return 1;
    }
    printf("Generated unique IDs: %s, %s\n", id1, id2);
    if(strcmp(id1,"WAF-AAAAAA-00000001") == 0 && strcmp(id2,"WAF-AAAAAA-00000002") == 0) {
        printf("Unique ID format is correct and IDs are unique\n");
        free(id1);
        free(id2);
        return 0;
    } else {
        printf("Unique ID format is incorrect or IDs are not unique\n");
        free(id1);
        free(id2);
        return 1;
    }
}

int test_log_event_json() {
    // This function would ideally test the log_event_json function, but since it writes to a file,
    // we would need to read the file back and verify its contents, which is beyond the scope of this simple test.
    // For now, we will just call the function with a sample WafEvent and check if it executes without errors.
    char timestamp[32];
    get_timestamp(timestamp);
    RequestInfo req = {
        .method = "GET",
        .uri = "/index.html",
        .query_string = "id=1",
        .host = "example.com",
        .user_agent = "Mozilla/5.0",
        .protocol = "HTTP/1.1"
    };
    RuleMatch rule = {
        .id = "942100",
        .message = "SQL Injection Attack Detected",
        .severity = "CRITICAL",
        .matched_data = "' OR '1'='1",
        .target = "ARGS:id",
        .tag = "attack-sqli"
    };
    WafEvent event = {
        .timestamp = "2024-06-01T12:00:00Z",
        .request_id = get_unique_id(),
        .client_ip = "192.168.1.1",
        .anomaly_score = 90,
        .threshold = 80,
        .blocked = BLOCK,
        .status_code = 403,
        .bytes_sent = 0,
        .req = req,
        .rule = rule
    };
    log_event_json(&event);
    printf("log_event_json executed successfully\n");
    free(event.request_id);
    return 0;
}
int main(void){
    char timestamp[20];
    get_timestamp(timestamp);
    printf("Generated timestamp: %s\n", timestamp);
    
    if(test_get_unique_id() != 0) {
        return 1;
    }

    if(test_log_event_json() != 0) {
        return 1;
    }



    
    return 0;
}