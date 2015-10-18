/* ========================================================================
   File: shift_attack.cpp
   Date: Apr. 28/15
   Revision: 1
   Creator: Brendan Duke
   Notice: (C) Copyright 2015 by BRD Inc. All Rights Reserved.
   ======================================================================== */

#include "crypt_helper.h"

int main()
{
    char *Cipher = getenv("CIPHER");
    Stopif(!Cipher, "No CIPHER env variable");
    uint32 CipherLength = strlen(Cipher);

    uint32 BestShift = GetBestShiftAmount(Cipher, CipherLength, 1);

    char Message[CipherLength + 1];
    Message[CipherLength] = 0;
    for (uint32 CipherIndex = 0; CipherIndex < CipherLength; ++CipherIndex) {
        Message[CipherIndex] = ShiftChar(Cipher[CipherIndex], BestShift);
    }
    printf("%s\n", Message);
}
