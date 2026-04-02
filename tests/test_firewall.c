#include "../lib/libinjection.h"
#include <stdio.h>
#include <string.h>

int main() {
    const char* input = "1' OR '1'='1";
    char fingerprint[8];
    int is_sqli;

    is_sqli = libinjection_sqli(input, strlen(input), fingerprint);

    if (is_sqli) {
        printf("Alerte ! Injection SQL détectée. Empreinte : %s\n", fingerprint);
    } else {
        printf("L'entrée est saine.\n");
    }

    return 0;
}