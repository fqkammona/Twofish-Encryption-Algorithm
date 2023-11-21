#include <stdio.h>
#include <string.h>
#include "twofish.h"

// Test function for plaintextToHex
int testPlaintextToHex() {
    const char *testString = "Welcome Twofish";
    char hexOutput[100]; // Ensure this is large enough

    plaintextToHex(testString, hexOutput);

    const char *expectedOutput = "57 65 6C 63 6F 6D 65 20 54 77 6F 66 69 73 68";
    if (strcmp(hexOutput, expectedOutput) == 0) {
        return 1; // Test passed
    } else {
        printf("Test failed: Incorrect hex output for plaintextToHex.\n");
        printf("Expected: %s\n", expectedOutput);
        printf("Got: %s\n", hexOutput);
        return 0; // Test failed
    }
}

int testInputWhitening128() {
    uint32_t plaintext[4] = {0x00000000, 0x00000000, 0x00000000, 0x00000000};
    uint32_t key[4] = {0x00000000, 0x00000000, 0x00000000, 0x00000000};
    uint32_t expectedOutput[4] = {0x00000000, 0x00000000, 0x00000000, 0x00000000};
    uint32_t whitenedText[4];

    inputWhitening(plaintext, key, whitenedText);

    for (int i = 0; i < 4; i++) {
        if (whitenedText[i] != expectedOutput[i]) {
            printf("Test failed at index %d: Expected 0x%08x, got 0x%08x\n", i, expectedOutput[i], whitenedText[i]);
            return 0; // Test failed
        }
    }
    return 1; // Test passed
}

// Additional test functions can be defined here
int main() {
    int allTestsPassed = 1;

    // Run testPlaintextToHex
    if (!testPlaintextToHex()) {
        allTestsPassed = 0;
    }

    // Additional test calls can be added here
    if (allTestsPassed) {
        printf("All tests passed.\n");
    } else {
        printf("Some tests failed.\n");
    }

    return !allTestsPassed;
}

