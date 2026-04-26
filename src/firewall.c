#include <stdbool.h>
#include <string.h>

#include "../inc/request_parser.h"

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