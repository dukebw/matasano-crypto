/* ========================================================================
   File: byte_xor_cipher.cpp
   Date: Apr. 16/15
   Revision: 1
   Creator: Brendan Duke
   Notice: (C) Copyright 2015 by BRD Inc. All Rights Reserved.
   ======================================================================== */

#include "helper.h"

int main(int argc, char **argv)
{
    char Ciphertext[] = "1b37373331363f78151b7f2b783431333d78397828372"
                        "d363c78373e783a393b3736";
    uint32 CipherLength = strlen(Ciphertext);
    uint32 ResultStringLength = CipherLength/2 + 1;
    char ResultString[ResultStringLength];
    ByteCipherDecodeString(ResultString, Ciphertext, CipherLength);
    printf("%s\n", ResultString);
}
