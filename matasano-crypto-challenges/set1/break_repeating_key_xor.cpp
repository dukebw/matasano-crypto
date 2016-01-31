/* ========================================================================
   File: break_repeating_key_xor.cpp
   Date: May 2/15
   Revision: 1
   Creator: Brendan Duke
   Notice: (C) Copyright 2015 by BRD Inc. All Rights Reserved.
   ======================================================================== */

#include "helper.h"

// NOTE(brendan): number of blocks to average over when calculating
// HammingDistance
#define HAMMING_BLOCKS_COUNT 16

// NOTE(brendan): INPUT: digit in base 64. OUTPUT: that digit translated to
// a uint32, or -1 if the given char was not a valid base 64 digit.
internal uint32
Base64ToUInt(char Base64Digit)
{
    if ((Base64Digit >= 'A') && (Base64Digit <= 'Z')) {
        return Base64Digit - 'A';
    } else if ((Base64Digit >= 'a') && (Base64Digit <= 'z')) {
        return Base64Digit - 'a' + 26;
    } else if ((Base64Digit >= '0') && (Base64Digit <= '9')) {
        return Base64Digit - '0' + 52;
    } else if (Base64Digit == '+') {
        return 62;
    } else if (Base64Digit == '/') {
        return 63;
    }
    Stopif(true, "Bad Base64Digit passed to Base64ToUint");
}

#if 1
int main()
{
    // NOTE(brendan): expecting base 64 cipher
    char *Cipher = getenv("CIPHER");
    Stopif(!Cipher, "No CIPHER env variable");
    uint32 CipherLength = strlen(Cipher);
    // NOTE(brendan): Note that here we force the CIPHER to be byte-aligned,
    // i.e. the number of base64 characters is a multiple of 4. Otherwise we
    // would have to take into account padding characters '=' and '==', or
    // just read the characters from left to right.
    Stopif((CipherLength % 4) == 1, "Bad CipherLength (should be padded)");

    // NOTE(brendan): length needed to store ByteCipher corresponding to
    // Base64Cipher. Last element should be 0
    uint32 ByteCipherLength = (CipherLength/4)*3;
    if (Cipher[CipherLength - 1] == '=') {
        if (Cipher[CipherLength - 2] == '=') {
            ByteCipherLength -= 2;
        }
        else {
            ByteCipherLength -= 1;
        }
    }
    char ByteCipher[ByteCipherLength + 1];
    ByteCipher[ByteCipherLength] = 0;
    // NOTE(brendan): translate CIPHER from base64 to base256 (ASCII)
    for (uint32 CipherIndex = 0, ByteIndex = 0;
         CipherIndex < CipherLength;
         ++CipherIndex) {
        // NOTE(brendan): Break early if last one or two Base64 digits were
        // '=' padding
        if (ByteIndex >= ByteCipherLength) {
            break;
        }
        // NOTE(brendan): uint8 used so that we shift out bits we don't want
        uint8 Base64Digit = Base64ToUInt(Cipher[CipherIndex]);
        switch (CipherIndex % 4) {
            case 0:
            {
                ByteCipher[ByteIndex] = Base64Digit << 2;
            } break;
            case 1:
            {
                ByteCipher[ByteIndex] |= Base64Digit >> 4;
                ByteCipher[ByteIndex + 1] = Base64Digit << 4;
                ++ByteIndex;
            } break;
            case 2:
            {
                ByteCipher[ByteIndex] |= Base64Digit >> 2;
                ByteCipher[ByteIndex + 1] = Base64Digit << 6;
                ++ByteIndex;
            } break;
            case 3:
            {
                ByteCipher[ByteIndex] |= Base64Digit;
                ++ByteIndex;
            } break;
        }
    }

    uint32 BitInHexDigit[] = {0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4};
    // NOTE(brendan): For each KeySize (between 2 and 40) take the first
    // KeySize worth of bytes and the second KeySize worth of bytes and find
    // the edit distance between them.
    // Normalize the result by dividing by KeySize
    // The KeySize with the smallest normalized edit distance is probably the
    // key. We proceed with the KeySizes corresponding to the smallest four
    // edit distances.
    real32 MinNormalizedDistance = INFINITY;
    uint32 BestKeySize;
    for (uint32 KeySize = 2; KeySize <= 40; ++KeySize) {
        uint32 HammingDistance = 0;
        for (uint32 BlockIndex = 0;
             BlockIndex < HAMMING_BLOCKS_COUNT;
             ++BlockIndex) {
            for (uint32 ByteIndex = 0; ByteIndex < KeySize; ++ByteIndex) {
                uint8 ByteA = ByteCipher[BlockIndex*KeySize + ByteIndex];
                uint8 ByteB = ByteCipher[BlockIndex*KeySize + KeySize +
                                         ByteIndex];
                uint8 DigitsXORed = (ByteA ^ ByteB);
                HammingDistance += BitInHexDigit[DigitsXORed & 0xf];
                HammingDistance += BitInHexDigit[DigitsXORed >> 4];
            }
        }
        real32 NormalizedDistance = (real32)HammingDistance/(real32)KeySize;
        if (NormalizedDistance < MinNormalizedDistance) {
            MinNormalizedDistance = NormalizedDistance;
            BestKeySize = KeySize;
        }
    }
    // NOTE(brendan): Here we are transposing the cipher into blocks, where
    // e.g. if the BestKeySize is 5 then the first block is element 0,6,11,...,
    // 2nd block is 1,7,12,... etc.
    // We are then solving each block as we would a single-key cipher
    uint32 BlockLength = ByteCipherLength/BestKeySize;
    char CipherBlocks[BestKeySize][BlockLength];
    for (uint32 ByteIndex = 0; ByteIndex < ByteCipherLength; ++ByteIndex) {
        uint32 BlockIndex = ByteIndex%BestKeySize;
        uint32 IndexInBlock = ByteIndex/BestKeySize;
        CipherBlocks[BlockIndex][IndexInBlock] = ByteCipher[ByteIndex];
    }
    uint8 VigenereKey[BestKeySize];
    for (uint32 BlockIndex = 0; BlockIndex < BestKeySize; ++BlockIndex) {
        char TempBlock[BlockLength];
        char *CipherBlockStart = (char *)CipherBlocks + BlockIndex*BlockLength;
        VigenereKey[BlockIndex] = ByteCipherAsciiDecode(TempBlock,
                                                        CipherBlockStart,
                                                        BlockLength);
    }
    char PlaintextGuess[ByteCipherLength + 1];
    PlaintextGuess[ByteCipherLength] = 0;
    for (uint32 PlaintextIndex = 0;
         PlaintextIndex < ByteCipherLength;
         ++PlaintextIndex) {
        PlaintextGuess[PlaintextIndex] = ByteCipher[PlaintextIndex] ^
                                         VigenereKey[PlaintextIndex%BestKeySize];
    }
    printf("%s\n", PlaintextGuess);
}
#endif
