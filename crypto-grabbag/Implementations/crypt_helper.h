#ifndef CRYPT_HELPER_H
#define CRYPT_HELPER_H

#include "allheads.h"

#pragma GCC diagnostic ignored "-Wunused-function"

#define ALPHABET_SIZE 26

global_variable real32 LetterFrequencies[] = {
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094,
    0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929,
    0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.02361, 0.00150,
    0.01974, 0.00074
};

// NOTE(brendan): INPUT: character to shift mod 26, shift amount (assumed to be
// in [0, 25]. OUTPUT: corresponding lower-case character, shifted mod 26
internal char
ShiftChar(char ToShiftChar, uint32 ShiftAmount)
{
    char Result;
    uint32 PreModChar = tolower(ToShiftChar) + ShiftAmount;
    if (PreModChar <= 'z') {
        Result = PreModChar;
    } else {
        Result = PreModChar - 26;
    }
    return Result;
}

// NOTE(brendan): INPUT: Cipher, its length and the length of the key.
// OUTPUT: the best shift amount (the shift amount that makes the Cipher
// closest to english-language letter frequency)
internal uint32
GetBestShiftAmount(char *Cipher, uint32 CipherLength, uint32 KeyLength)
{
    uint32 CharCounts[ALPHABET_SIZE] = {};
    uint32 Result = 0;
    real32 BestShiftDelta = INFINITY;
 
    for (uint32 ShiftAmount = 0; ShiftAmount < ALPHABET_SIZE; ++ShiftAmount) {
        for (uint32 CipherIndex = 0;
             CipherIndex < CipherLength;
             CipherIndex += KeyLength) {
            uint32 AlphabetOffset =
                ShiftChar(Cipher[CipherIndex], ShiftAmount) - 'a';
            ++CharCounts[AlphabetOffset];
        }
        real32 ShiftFrequencySum = 0.0f;
        for (uint32 CharIndex = 0; CharIndex < ALPHABET_SIZE; ++CharIndex) {
            real32 KeyLetterFreq =
                (real32)CharCounts[CharIndex]/(real32)CipherLength;
            ShiftFrequencySum += KeyLetterFreq*LetterFrequencies[CharIndex];
        }
        real32 ShiftDelta = fabs(ShiftFrequencySum - 0.065);
        if (ShiftDelta < BestShiftDelta) {
            Result = ShiftAmount;
            BestShiftDelta = ShiftDelta;
        }
        memset((void *)CharCounts, 0, ALPHABET_SIZE*sizeof(CharCounts[0]));
    }

    return Result;
}

#endif /* CRYPT_HELPER_H */
