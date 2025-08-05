//
// Created by tau on 2/08/25.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tgmath.h>
#include <time.h>

#include "include/library.h"

int main() {
    const char* key = "A5JFOWQWU2MG7LUG";

    uint64_t counter = Totop_topt_get_counter(30);

    int decoded_keylength = 0;
    unsigned char* decoded_key = Totop_decode_base32(key, strlen(key), &decoded_keylength);

    unsigned int code = Totop_get_code(TOTOP_SHA1, decoded_key, (int) decoded_keylength, counter, 6);

    printf("Your code is: %i", code);

    free(decoded_key);
}