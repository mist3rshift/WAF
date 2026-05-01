#ifndef INTERNAL_LOG_H
#define INTERNAL_LOG_H
#include <stdint.h>
#define MAX_URI_LEN         1024
#define MAX_QUERY_LEN       2048
#define MAX_HEADER_VAL      512

typedef struct {
    char method[12];         // GET, POST, OPTIONS...
    char protocol[16];       // HTTP/1.1
    char host[256];          
    char user_agent[MAX_HEADER_VAL];
    char content_type[128];
    
    // Security Zones
    char uri[MAX_URI_LEN];
    char query_string[MAX_QUERY_LEN];
    
    uint32_t content_length;
} RequestInfo;

typedef struct {
    char id[16];           // "942100"
    char message[128];     // "SQL Injection Attack Detected"
    char severity[16];    // "CRITICAL", "WARNING"
    char matched_data[256];// "' OR '1'='1"
    char target[64];       // "ARGS:id"
    char tag[32];          // "attack-sqli"
} RuleMatch;

typedef struct {
    char timestamp[32];    // ISO 8601 format
    char event_type[20];   // "waf_event"
    char *request_id;      // Unique ID generated
    char client_ip[46];    // Supports IPv6 addresses
    
    int anomaly_score;     // 0-100 based on matched rules
    int threshold;
    int blocked;         // true if the request was blocked         
    int status_code;       // 200, 403, 502
    int bytes_sent;       // content length
    
    RequestInfo req;       
    RuleMatch rule;        
} WafEvent;

enum BLOCK_DECISION {
    ALLOW = 0,
    BLOCK = 1
};

void get_timestamp(char *target);
char* get_unique_id();
void write_log(const char *log_entry);
void log_event_json( const WafEvent* event);


#endif

