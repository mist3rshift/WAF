#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "../inc/request_parser.h"
#include "../inc/firewall.h"
#include "../lib/cJSON.h"
#include "../inc/config.h"

#define INITIAL_CAPACITY 10
#define CAPACITY_GROWTH_FACTOR 1.5

static rule* rules_db = NULL;
static int rules_count = 0;
static int rules_capacity = 0;

bool is_malicious(String target){
    char temp[1024];
    int len = target.len < 1023 ? target.len : 1023;
    memcpy(temp, target.ptr, len);
    temp[len] = '\0';

    if (strstr(temp, "<script>") != NULL) {
        return true;
    }
    if (strstr(temp, "../") != NULL) {
        return true;
    }
    if (strstr(temp, "OR 1=1") != NULL) {
        return true;
    }

    return false;
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

        // Validate field presence and types
        if (cJSON_IsString(id_item) && cJSON_IsNumber(type_item) && 
            cJSON_IsString(pattern_item) && cJSON_IsString(name_item) && 
            cJSON_IsNumber(score_item)) {

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


