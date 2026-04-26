#include "../lib/libinjection.h"
#include <stdio.h>
#include <string.h>

int main() {
    const char* input1 = "1' OR '1'='1";
    const char* input2 = "../";
    const char* input3 = "<script>";
    char fingerprint[8];
    int is_sqli1;
    int is_sqli2;
    int is_sqli3;


    is_sqli1 = libinjection_sqli(input1, strlen(input1), fingerprint);
    is_sqli2 = libinjection_sqli(input2, strlen(input2), fingerprint);
    is_sqli3 = libinjection_sqli(input3, strlen(input3), fingerprint);

    if (is_sqli1) {
        printf("Alerte ! Injection SQL détectée. Empreinte : %s\n", fingerprint);
    } else {
        printf("L'entrée est saine.\n");
    }

    if (is_sqli2) {
        printf("Alerte ! Injection SQL détectée. Empreinte : %s\n", fingerprint);
    } else {
        printf("L'entrée est saine.\n");
    }

    if (is_sqli3) {
        printf("Alerte ! Injection SQL détectée. Empreinte : %s\n", fingerprint);
    } else {
        printf("L'entrée est saine.\n");
    }

    return 0;
}