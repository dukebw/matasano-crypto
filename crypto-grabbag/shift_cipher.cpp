/* ========================================================================
   File:  shift_cipher.cpp
   Date: Apr. 28/15
   Revision: 1
   Creator: Brendan Duke
   Notice: (C) Copyright 2015 by BRD Inc. All Rights Reserved.
   ======================================================================== */

#include "crypt_helper.h"

int main()
{
    char *Message = getenv("MESSAGE");
    Stopif(!Message, "No message env variable");
    char *ShiftString = getenv("KEY");
    Stopif(!ShiftString, "No shift env variable");
    Stopif(!isalpha(*ShiftString), "Bad key");

    uint32 ShiftAmount = tolower(*ShiftString) - 'a';
    uint32 MessageLength = strlen(Message);
    char Ciphertext[MessageLength + 1];
    for (uint32 MessageIndex = 0;
         MessageIndex < MessageLength;
         ++MessageIndex) {
        Ciphertext[MessageIndex] = ShiftChar(Message[MessageIndex], ShiftAmount);
    }
    Ciphertext[MessageLength] = 0;
    printf("%s\n", Ciphertext);
}
