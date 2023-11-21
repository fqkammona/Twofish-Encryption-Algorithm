#ifndef TWOFISH_H
#define TWOFISH_H

#include <stdint.h>

void plaintextToHex(const char *plaintext, char *hexOutput);
void inputWhitening(uint32_t *plaintext, uint32_t *key, uint32_t *whitenedText); 

#endif // TWOFISH_H

