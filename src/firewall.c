#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <regex.h>

#include "../inc/request_parser.h"
#include "../inc/firewall.h"
#include "../lib/cJSON.h"
#include "../inc/config.h"
#include "../inc/internal_log.h"

#define INITIAL_CAPACITY 10
#define CAPACITY_GROWTH_FACTOR 1.5

static rule* rules_db = NULL;
static int rules_count = 0;
static int rules_capacity = 0;

/**
 * @brief Get severity string based on score
 */
const char* get_severity_str(int score) {
    if (score >= 5) return "CRITICAL";
    if (score >= 4) return "HIGH";
    if (score >= 2) return "MEDIUM";
    return "LOW";
}

/**
 * @brief Replaces C-style comments (/* ... *\/) with spaces.
 * @param str The string to process (modified in-place).
 */
void strip_comments(char* str) {
    if (!str) return;
    
    char* start;
    char* end;
    
    // Find the beginning of a comment block
    while ((start = strstr(str, "/*")) != NULL) {
        // Find the end of the comment block
        end = strstr(start + 2, "*/");
        if (end != NULL) {
            // Overwrite the entire block (including /* and */) with spaces.
            // cJSON naturally ignores whitespace.
            memset(start, ' ', (end + 2) - start);
        } else {
            // Malformed comment: erase from start to the end of the string
            memset(start, ' ', strlen(start));
            break;
        }
    }
}
/**
 * @brief Loads WAF rules from a JSON configuration file.
 * @param rules_config_path Path to the .conf or .json file.
 * @return Number of rules loaded, or -1 on failure.
 */
int load_rules(char* rules_config_path) {
    if (rules_config_path == NULL) return -1;

    FILE* file = fopen(rules_config_path, "r");
    if (file == NULL) return -1;

    // Determine file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size <= 0) {
        fclose(file);
        return -1;
    }

    // Allocate buffer and read content
    char* buffer = (char*)malloc(file_size + 1);
    if (buffer == NULL) {
        fclose(file);
        return -1;
    }

    size_t read_size = fread(buffer, 1, file_size, file);
    fclose(file);
    buffer[read_size] = '\0';

    // --- STEP 1: Pre-process the buffer to remove comments ---
    strip_comments(buffer);

    // --- STEP 2: Parse cleaned JSON ---
    cJSON* json = cJSON_Parse(buffer);
    free(buffer); // Text buffer no longer needed after parsing

    if (json == NULL) return -1;

    // --- STEP 3: Reset local database ---
    if (rules_db != NULL) {
        free(rules_db);
        rules_db = NULL;
    }
    rules_count = 0;

    // Initial allocation
    rules_capacity = INITIAL_CAPACITY;
    rules_db = (rule*)malloc(rules_capacity * sizeof(rule));
    if (rules_db == NULL) {
        cJSON_Delete(json);
        return -1;
    }

    // --- STEP 4: Process JSON array ---
    int array_size = cJSON_GetArraySize(json);
    for (int i = 0; i < array_size; i++) {
        cJSON* rule_item = cJSON_GetArrayItem(json, i);
        
        cJSON* id_item      = cJSON_GetObjectItem(rule_item, "id");
        cJSON* type_item    = cJSON_GetObjectItem(rule_item, "type");
        cJSON* pattern_item = cJSON_GetObjectItem(rule_item, "pattern");
        cJSON* name_item    = cJSON_GetObjectItem(rule_item, "name");
        cJSON* score_item   = cJSON_GetObjectItem(rule_item, "score");
        cJSON* regex_item   = cJSON_GetObjectItem(rule_item, "is_regex");

        // Validate field presence and types
        if (cJSON_IsString(id_item) && cJSON_IsNumber(type_item) && 
            cJSON_IsString(pattern_item) && cJSON_IsString(name_item) && 
            cJSON_IsNumber(score_item) && cJSON_IsNumber(regex_item)) {

            // Dynamic resizing
            if (rules_count >= rules_capacity) {
                int new_capacity = rules_capacity + 16; 
                rule* temp = (rule*)realloc(rules_db, new_capacity * sizeof(rule));
                if (temp == NULL) break; 
                rules_db = temp;
                rules_capacity = new_capacity;
            }

            // Safe copy to memory
            strncpy(rules_db[rules_count].id, id_item->valuestring, sizeof(rules_db[rules_count].id) - 1);
            rules_db[rules_count].id[sizeof(rules_db[rules_count].id) - 1] = '\0';

            rules_db[rules_count].type = type_item->valueint;

            strncpy(rules_db[rules_count].pattern, pattern_item->valuestring, sizeof(rules_db[rules_count].pattern) - 1);
            rules_db[rules_count].pattern[sizeof(rules_db[rules_count].pattern) - 1] = '\0';

            strncpy(rules_db[rules_count].name, name_item->valuestring, sizeof(rules_db[rules_count].name) - 1);
            rules_db[rules_count].name[sizeof(rules_db[rules_count].name) - 1] = '\0';

            rules_db[rules_count].score = score_item->valueint;

            rules_db[rules_count].is_regex = regex_item->valueint;

            rules_count++;
        }
    }

    cJSON_Delete(json);
    return rules_count;
}

/**
 * Get the number of loaded rules
 */
int get_rules_count(void) {
    return rules_count;
}

/**
 * Get a rule by index
 */
rule* get_rule(int index) {
    if (rules_db == NULL || index < 0 || index >= rules_count) {
        return NULL;
    }
    return &rules_db[index];
}

/**
 * Get a rule by ID
 */
rule* get_rule_by_id(const char* rule_id) {
    if (rule_id == NULL || rules_db == NULL) {
        return NULL;
    }
    
    for (int i = 0; i < rules_count; i++) {
        if (strcmp(rules_db[i].id, rule_id) == 0) {
            return &rules_db[i];
        }
    }
    return NULL;
}

/**
 * Free allocated rules memory
 */
void free_rules(void) {
    if (rules_db != NULL) {
        free(rules_db);
        rules_db = NULL;
    }
    rules_count = 0;
    rules_capacity = 0;
}
/**
 * @brief Helper: Decodes URL-encoded strings in-place.
 * Converts characters like %27 to ' and + to space.
 */
void url_decode_inplace(char *str) {
    if (!str) return;
    
    char *p = str;
    char *q = str;
    char hex[3] = {0};

    while (*p) {
        if (*p == '%' && isxdigit(p[1]) && isxdigit(p[2])) {
            hex[0] = p[1];
            hex[1] = p[2];
            *q = (char)strtol(hex, NULL, 16);
            p += 3;
        } else if (*p == '+') {
            *q = ' ';
            p++;
        } else {
            *q = *p;
            p++;
        }
        q++;
    }
    *q = '\0';
}

/**
 * @brief Maps generic parsed data into the WAF-specific Security Context.
 * 
 * Handles non-null-terminated strings from the parser, splits URI/Query,
 * and extracts specific high-value headers.
 */
void extract_security_context(const Request *raw_req, RequestInfo *waf_req) {
    if (!raw_req || !waf_req) return;

    // 1. Clear the destination structure to prevent garbage data
    memset(waf_req, 0, sizeof(RequestInfo));

    // 2. Extract Method
    snprintf(waf_req->method, sizeof(waf_req->method), "%.*s", 
             (int)raw_req->method.len, raw_req->method.ptr);

    // 3. Extract Protocol (Convert float minor to string)
    snprintf(waf_req->protocol, sizeof(waf_req->protocol), "HTTP/1.%.0f", raw_req->minor);

    // 4. Split Target into URI and Query String
    // HTTP Target usually looks like: /path/to/page?id=123
    char full_target[MAX_URI_LEN + MAX_QUERY_LEN] = {0};
    snprintf(full_target, sizeof(full_target), "%.*s", 
             (int)raw_req->target.len, raw_req->target.ptr);

    char *query_ptr = strchr(full_target, '?');
    if (query_ptr) {
        // Copy query string (everything after '?')
        strncpy(waf_req->query_string, query_ptr + 1, sizeof(waf_req->query_string) - 1);
        
        // Terminate full_target at '?' to leave only the URI path
        *query_ptr = '\0';
        strncpy(waf_req->uri, full_target, sizeof(waf_req->uri) - 1);
    } else {
        // No query string present
        strncpy(waf_req->uri, full_target, sizeof(waf_req->uri) - 1);
    }

    // 5. Decode URL encoding for both URI and Query String
    // This is vital so the inspection engine sees the actual payload
    url_decode_inplace(waf_req->uri);
    url_decode_inplace(waf_req->query_string);

    // 6. Loop through headers to find security-critical fields
    for (int i = 0; i < raw_req->num_headers; i++) {
        const char *h_name = raw_req->headers[i].name.ptr;
        size_t h_name_len = raw_req->headers[i].name.len;
        const char *h_val = raw_req->headers[i].value.ptr;
        size_t h_val_len = raw_req->headers[i].value.len;

        // Host header
        if (h_name_len == 4 && strncasecmp(h_name, "Host", 4) == 0) {
            snprintf(waf_req->host, sizeof(waf_req->host), "%.*s", (int)h_val_len, h_val);
        }
        // User-Agent header
        else if (h_name_len == 10 && strncasecmp(h_name, "User-Agent", 10) == 0) {
            snprintf(waf_req->user_agent, sizeof(waf_req->user_agent), "%.*s", (int)h_val_len, h_val);
        }
        // Content-Type (useful for detecting file upload attacks)
        else if (h_name_len == 12 && strncasecmp(h_name, "Content-Type", 12) == 0) {
            // Check for potential buffer truncation or malformed headers here if needed
        }
        // Content-Length
        else if (h_name_len == 14 && strncasecmp(h_name, "Content-Length", 14) == 0) {
            char temp_len[16] = {0};
            snprintf(temp_len, sizeof(temp_len), "%.*s", (int)h_val_len, h_val);
            waf_req->content_length = (uint32_t)atoi(temp_len);
        }
    }
}



/**
 * @brief Creates a lowercase copy of the source string for case-insensitive matching.
 */
void normalize_target(char *dest, const char *src, size_t max_len) {
    if (!src || !dest) return;
    int len = 0;
    for (size_t i = 0; i < max_len - 1 && src[i]; i++) {
        dest[i] = (char)tolower((unsigned char)src[i]);
        len++;
    }
    dest[len] = '\0';
}

/**
 * @brief Scans a specific string against the rules database.
 * @param data The string to inspect (e.g., query string).
 * @param target_name The name of the field being inspected (for logging).
 * @param event Pointer to the current WafEvent to update.
 */
void inspect_data(const char *data, const char *target_name, WafEvent *event) {
    if (!data || strlen(data) == 0) return;

    char clean_data[1024];
    normalize_target(clean_data, data, sizeof(clean_data));

    for (int i = 0; i < get_rules_count(); i++) {
        rule *r = get_rule(i);

        bool matched = false;
        regex_t compiled;
        
        if (r->is_regex) {
            if (regcomp(&compiled, r->pattern, REG_EXTENDED | REG_ICASE) != 0) {
                // pattern invalide, on skip cette règle
                continue;
            }
            matched = (regexec(&compiled, clean_data, 0, NULL, 0) == 0);
            regfree(&compiled);
        }
        else {
            // Use strstr on the normalized data (case-insensitive search)
            matched = (strstr(clean_data, r->pattern) != NULL);
        }
        
        if (matched) {
                event->anomaly_score += r->score;

                // Update RuleMatch details if this is the first match 
                // or if it has a higher score than the previous match recorded
                if (strlen(event->rule.id) == 0 || r->score > event->anomaly_score - r->score) {
                    strncpy(event->rule.id, r->id, sizeof(event->rule.id) - 1);
                    strncpy(event->rule.message, r->name, sizeof(event->rule.message) - 1);
                    strncpy(event->rule.severity, get_severity_str(r->score), sizeof(event->rule.severity) - 1);
                    strncpy(event->rule.matched_data, r->pattern, sizeof(event->rule.matched_data) - 1);
                    strncpy(event->rule.target, target_name, sizeof(event->rule.target) - 1);
                    // Tag is derived from type (e.g., SQLI, XSS)
                    snprintf(event->rule.tag, sizeof(event->rule.tag), "threat_type_%d", r->type);
                }
        }
    
    }
}


/**
 * @brief Orchestrates the full analysis of the request.
 * 
 * This version takes the raw Request struct from the parser, 
 * populates the WafEvent's internal RequestInfo, and performs 
 * the security inspection.
 * 
 * @param raw_req The raw data from the HTTP parser.
 * @param event The event structure to be filled and logged.
 * @return 1 if the request is blocked, 0 if allowed.
 */
int perform_waf_analysis(const Request *raw_req, WafEvent *event) {
    // 1. Basic Initialization
    event->anomaly_score = 0;
    event->blocked = 0;
    event->status_code = 200; // Default to OK
    
    // 2. Data Extraction & Mapping
    // We fill event->req (RequestInfo) using the data from raw_req (Request)
    // This handles pointer-to-buffer conversion and null-termination.
    extract_security_context(raw_req, &event->req);

    // 3. Security Inspection
    // We now use the fixed buffers in event->req for analysis.
    // This is safer and easier to debug.
    inspect_data(event->req.uri, "URI", event);
    inspect_data(event->req.query_string, "QUERY_STRING", event);
    inspect_data(event->req.user_agent, "USER_AGENT", event);
    inspect_data(event->req.host, "HOST", event);

    // 4. Decision Logic
    // event->threshold should be set earlier (e.g., in handle_client)
    if (event->anomaly_score >= event->threshold) {
        event->status_code = 403; // Forbidden
        
        // BLOCK_ENABLE is typically a macro or global config variable
        if (BLOCK_ENABLE) {
            event->blocked = 1;
            return 1; // Signal the proxy to drop the connection
        }
    }

    return 0; // Allow the request to proceed to the backend
}


