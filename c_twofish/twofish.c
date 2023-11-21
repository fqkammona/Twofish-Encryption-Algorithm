#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "twofish.h"

// Function to convert plaintext to hex
void plaintextToHex(const char *plaintext, char *hexOutput) {
    int len = strlen(plaintext);
    for (int i = 0; i < len; i++) {
        sprintf(&hexOutput[i * 3], "%02X ", plaintext[i]);
    }
    hexOutput[len * 3 - 1] = '\0'; // Remove the trailing space
}

// whitening
void inputWhitening(uint32_t *plaintext, uint32_t *key, uint32_t *whitenedText) {
    for (int i = 0; i <  4; i++) { // key_size = 128 bit = 4, 192 = 6, 256 = 8
        whitenedText[i] = plaintext[i] ^ key[i];
    }
}



