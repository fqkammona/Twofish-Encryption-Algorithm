#include <stdio.h>
#include <string.h>
#include "twofish.h"

int main() {
    char* str = getHelloWorldString();
    if (strcmp(str, "Hello, World!") == 0) {
        printf("Test passed: Correct string returned.\n");
    } else {
        printf("Test failed: Incorrect string returned.\n");
    }
    return 0;
}

