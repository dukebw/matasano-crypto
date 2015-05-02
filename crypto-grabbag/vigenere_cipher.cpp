/* ========================================================================
   File: vigenere_cipher.cpp
   Date: Apr. 28/15
   Revision: 1
   Creator: Brendan Duke
   Notice: (C) Copyright 2015 by BRD Inc. All Rights Reserved.
   ======================================================================== */

#include "crypt_helper.h"

int main()
{
    char *Message = getenv("MESSAGE");
    Stopif(!Message, return -1, "No message env variable");
    uint32 MessageLength = strlen(Message);
    char *Key = getenv("KEY");
    Stopif(!Key, return -1, "No shift env variable");
    uint32 KeyLength = strlen(Key);

    char Ciphertext[MessageLength + 1];
    Ciphertext[MessageLength] = 0;
    for (uint32 MessageIndex = 0, KeyIndex = 0;
         MessageIndex < MessageLength;
         ++MessageIndex,
         KeyIndex = (KeyIndex < (KeyLength - 1)) ? KeyIndex + 1 : 0) {
        uint32 ShiftAmount = tolower(Key[KeyIndex]) - 'a';
        Ciphertext[MessageIndex] = ShiftChar(Message[MessageIndex],
                                             ShiftAmount);
    }
    printf("%s\n", Ciphertext);
}
