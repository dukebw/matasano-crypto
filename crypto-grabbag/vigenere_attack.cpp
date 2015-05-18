/* ========================================================================
   File: vigenere_attack.cpp
   Date: Apr. 28/15
   Revision: 1
   Creator: Brendan Duke
   Notice: (C) Copyright 2015 by BRD Inc. All Rights Reserved.
   ======================================================================== */

#include "crypt_helper.h"

#define MAX_KEY_LENGTH 64

// BestKeyLength should be the SMALLEST KeyLength such that the sum (q_i)^2
// is sufficiently close to 0.065
int main()
{
    char *Cipher = getenv("CIPHER");
    Stopif(!Cipher, return -1, "No CIPHER env variable");
    uint32 CipherLength = strlen(Cipher);
    
    uint32 CharCounts[ALPHABET_SIZE] = {};
    uint32 BestKeyLength = 0;
    for (uint32 KeyLength = 1; KeyLength < MAX_KEY_LENGTH; ++KeyLength) {
        uint32 CheckedCipherChars = 0;
        for (uint32 CipherIndex = 0;
             CipherIndex < CipherLength;
             CipherIndex += KeyLength) {
            uint32 AlphabetOffset = Cipher[CipherIndex] - 'a';
            ++CharCounts[AlphabetOffset];
            ++CheckedCipherChars;
        }
        real32 ShiftFrequencySum = 0.0f;
        for (uint32 CharIndex = 0; CharIndex < ALPHABET_SIZE; ++CharIndex) {
            real32 KeyLetterFreq =
                (real32)CharCounts[CharIndex]/(real32)CheckedCipherChars;
            ShiftFrequencySum += KeyLetterFreq*KeyLetterFreq;
        }
        if (fabs(ShiftFrequencySum - 0.065) < fabs(ShiftFrequencySum - 0.038)) {
            BestKeyLength = KeyLength;
            break;
        }
        memset((void *)CharCounts, 0, ALPHABET_SIZE*sizeof(CharCounts[0]));
    }

    char Key[BestKeyLength + 1];
    Key[BestKeyLength] = 0;
    for (uint32 KeyIndex = 0; KeyIndex < BestKeyLength; ++KeyIndex) {
        // TODO(brendan): debugging this step
        Key[KeyIndex] = 
            'a' + GetBestShiftAmount(Cipher + KeyIndex,
                                     CipherLength - KeyIndex, BestKeyLength);
    }

    char Message[CipherLength + 1];
    Message[CipherLength] = 0;
    for (uint32 CipherIndex = 0; CipherIndex < CipherLength; ++CipherIndex) {
        Message[CipherIndex] = ShiftChar(Cipher[CipherIndex],
                                         Key[CipherIndex % BestKeyLength] - 'a');
    }

    printf("%s\n", Message);
}
