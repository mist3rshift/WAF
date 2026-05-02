#ifndef FIREWALL_H
#define FIREWALL_H

#include <stdbool.h>
#include "request_parser.h"
#include "internal_log.h"

typedef struct _rule {
    char id[16];         // uniq unique (ex: "SQL-001")
    int type;            // ThreatType (enum)
    char pattern[128];   // pattern to seach
    char name[64];       // Nom explicite
    int score;           // score 
    int is_regex;        // 0 pour strstr, 1 pour regexec
} rule;

typedef enum {
    THREAT_NONE = 0,
    THREAT_SQLI = 1,
    THREAT_XSS = 2,
    THREAT_PATH_TRAVERSAL = 3,
    THREAT_COMMAND_INJECTION = 4,
    THREAT_INVALID_METHOD = 101,
    THREAT_INVALID_HEADER = 102,
    THREAT_MALFORMED = 999
} ThreatType;

void strip_comments(char* str);

int load_rules(char* rules_config_path);

int get_rules_count(void);

rule* get_rule(int index);

rule* get_rule_by_id(const char* rule_id);

void free_rules(void);

void url_decode_inplace(char *str);

void normalize_target(char *dest, const char *src, size_t max_len);

void extract_security_context(const Request *raw_req, RequestInfo *waf_req);

void inspect_data(const char *data, const char *target_name, WafEvent *event);

int perform_waf_analysis(const Request *raw_req, WafEvent *event);

#endif