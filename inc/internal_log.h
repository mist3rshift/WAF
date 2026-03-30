#ifndef INTERNAL_LOG_H
#define INTERNAL_LOG_H

typedef struct 
{
    char method[8];
    char uri[256];
    char query_string[512];
    char host[256];
    char user_agent[256];
    char protocol[16];

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

