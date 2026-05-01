
#include "../lib/log.h"
#include "../lib/cJSON.h"
#include "../inc/internal_log.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/// @brief Generates a timestamp in the format "YYYY-MM-DD HH:MM:SS"
/// @param target Pointer to a character array where the timestamp will be stored
void get_timestamp(char *target){
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(target, 20, "%Y-%m-%d %H:%M:%S", t);
}

pthread_mutex_t id_mutex = PTHREAD_MUTEX_INITIALIZER;

/// @brief Generates a unique ID in the format "WAF-XXXXXX-XXXXXXXX" where X are letters and digits
/// @return Pointer to a dynamically allocated string containing the unique ID.
///         The caller is responsible for freeing this memory.
char* get_unique_id() {
    char *id = malloc(20);
    if (id == NULL) return NULL;

    // Static counter for incremental ID generation
    static unsigned long long counter = 0;

    pthread_mutex_lock(&id_mutex);
    counter++;
    pthread_mutex_unlock(&id_mutex);

    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char numset[] = "0123456789";
    
    // 8 digits increment first (0 to 99999999), then letters change
    unsigned int digit_value = counter % 100000000;
    unsigned long long letter_counter = counter / 100000000;
    
    // Generate 6 letters (base-26)
    char letters[7] = {0};
    for(int i = 5; i >= 0; i--) {
        letters[i] = charset[letter_counter % 26];
        letter_counter /= 26;
    }
    
    // Generate 8 digits (0-99999999)
    snprintf(id, 20, "WAF-%s-%08u", letters, digit_value);

    return id;
}

pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

/// @brief Writes a log entry to the log file in JSON format
/// @param log_entry The log entry to be written to the file
void write_log(const char *log_entry) {

    pthread_mutex_lock(&log_mutex);

    FILE *file = fopen("waf_log.json", "a");
    if (file == NULL) {
        log_error("Failed to open log file");
        pthread_mutex_unlock(&log_mutex);
        return;
    }
    fprintf(file, "%s\n", log_entry);
    fflush(file);
    fclose(file);
    pthread_mutex_unlock(&log_mutex);
}


/// @brief Generates a JSON log entry for a given event and writes it to the log file
/// @param event The WafEvent for which to generate a log entry
void log_event_json( const WafEvent* event){
    cJSON *log_entry = cJSON_CreateObject();
    if (log_entry == NULL) {
        log_error("Failed to create JSON object for log entry");
        return;
    }

    // Add basic fields
    cJSON_AddStringToObject(log_entry, "timestamp", event->timestamp);
    cJSON_AddStringToObject(log_entry, "event_type", "waf_event");
    cJSON_AddStringToObject(log_entry, "request_id", event->request_id);
    cJSON_AddStringToObject(log_entry, "severity", event->rule.severity);
    cJSON *source = cJSON_CreateObject();
    cJSON_AddStringToObject(source, "client_ip", event->client_ip);
    cJSON_AddItemToObject(log_entry, "source", source);
    cJSON *request = cJSON_CreateObject();
    cJSON_AddStringToObject(request, "method", event->req.method);
    cJSON_AddStringToObject(request, "uri", event->req.uri);
    cJSON_AddStringToObject(request, "query_string", event->req.query_string);
    cJSON_AddStringToObject(request, "host", event->req.host);
    cJSON_AddStringToObject(request, "user_agent", event->req.user_agent);
    cJSON_AddStringToObject(request, "protocol", event->req.protocol);
    cJSON_AddItemToObject(log_entry, "request", request);

    cJSON *matched_rule = cJSON_CreateObject();
    cJSON_AddStringToObject(matched_rule, "id", event->rule.id);
    cJSON_AddStringToObject(matched_rule, "message", event->rule.message);
    cJSON_AddStringToObject(matched_rule, "matched_data", event->rule.matched_data);
    cJSON_AddStringToObject(matched_rule, "target", event->rule.target);
    cJSON_AddStringToObject(matched_rule, "tag", event->rule.tag);
    cJSON_AddItemToObject(log_entry, "matched_rule", matched_rule);

    cJSON *crs = cJSON_CreateObject();
    cJSON_AddNumberToObject(crs, "anomaly_score", event->anomaly_score);
    cJSON_AddNumberToObject(crs, "threshold", event->threshold);
    cJSON_AddItemToObject(log_entry, "crs", crs);

    cJSON *action = cJSON_CreateObject();
    cJSON_AddNumberToObject(action, "final_decision", event->blocked);
    cJSON_AddItemToObject(log_entry, "action", action);

    cJSON *response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "status_code", event->status_code);
    cJSON_AddNumberToObject(response, "bytes_sent", event->bytes_sent);

    cJSON_AddItemToObject(log_entry, "response", response);

    // Convert JSON object to string
    char *log_entry_str = cJSON_PrintUnformatted(log_entry);
    if (log_entry_str == NULL) {
        log_error("Failed to convert JSON log entry to string");
        cJSON_Delete(log_entry);
        return;
    }
    // Write log entry to file
    write_log(log_entry_str);
    // Clean up
    cJSON_Delete(log_entry);
    free(log_entry_str);
}

