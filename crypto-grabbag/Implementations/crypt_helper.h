#ifndef CRYPT_HELPER_H
#define CRYPT_HELPER_H

#include "allheads.h"

#pragma GCC diagnostic ignored "-Wunused-function"

#define ALPHABET_SIZE 26

global_variable real32 LetterFrequencies[] =
{
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094,
    0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929,
    0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.02361, 0.00150,
    0.01974, 0.00074
};

// NOTE(brendan): INPUT: character to shift mod 26, shift amount (assumed to be
// in [0, 25]. OUTPUT: corresponding lower-case character, shifted mod 26
internal uint32
ShiftChar(uint32 ToShiftChar, uint32 ShiftAmount)
{
    // TODO(brendan): more checking
    Stopif(!(((ToShiftChar <= 'Z') && (ToShiftChar >= 'A')) ||
             ((ToShiftChar <= 'z') && (ToShiftChar >= 'a'))),
           return -1,
           "Bad input char");
    uint32 Result;
    uint32 PreModChar = tolower(ToShiftChar) + ShiftAmount;
    if (PreModChar <= 'z')
    {
        Result = PreModChar;
    }
    else
    {
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
 
    for (uint32 ShiftAmount = 0; ShiftAmount < ALPHABET_SIZE; ++ShiftAmount)
    {
        for (uint32 CipherIndex = 0;
             CipherIndex < CipherLength;
             CipherIndex += KeyLength)
        {
            uint32 AlphabetOffset = ShiftChar(Cipher[CipherIndex], ShiftAmount) - 'a';
            ++CharCounts[AlphabetOffset];
        }
        real32 ShiftFrequencySum = 0.0f;
        for (uint32 CharIndex = 0; CharIndex < ALPHABET_SIZE; ++CharIndex)
        {
            real32 KeyLetterFreq =
                (real32)CharCounts[CharIndex]/(real32)CipherLength;
            ShiftFrequencySum += KeyLetterFreq*LetterFrequencies[CharIndex];
        }
        real32 ShiftDelta = fabs(ShiftFrequencySum - 0.065);
        if (ShiftDelta < BestShiftDelta)
        {
            Result = ShiftAmount;
            BestShiftDelta = ShiftDelta;
        }
        memset((void *)CharCounts, 0, ALPHABET_SIZE*sizeof(CharCounts[0]));
    }

    return Result;
}

// NOTE(brendan): INPUT: digit in base 64. OUTPUT: that digit translated to
// a uint32, or -1 if the given char was not a valid base 64 digit.
internal uint32
Base64ToUInt(uint8 Base64Digit)
{
    if ((Base64Digit >= 'A') && (Base64Digit <= 'Z'))
    {
        return Base64Digit - 'A';
    }
    else if ((Base64Digit >= 'a') && (Base64Digit <= 'z'))
    {
        return Base64Digit - 'a' + 26;
    }
    else if ((Base64Digit >= '0') && (Base64Digit <= '9'))
    {
        return Base64Digit - '0' + 52;
    }
    else if (Base64Digit == '+')
    {
        return 62;
    }
    else if (Base64Digit == '/')
    {
        return 63;
    }
    Stopif(true, return -1, "Bad Base64Digit passed to Base64ToUint");
}

// NOTE(brendan): INPUT: OUTPUT:
internal uint32
Base64ToAscii(uint8 *AsciiString, uint8 *Base64String, uint32 Base64StringLength)
{
    // NOTE(brendan): Note that here we force the Base64String to be byte-aligned,
    // i.e. the number of base64 characters is a multiple of 4. Otherwise we
    // would have to take into account padding characters '=' and '==', or
    // just read the characters from left to right.
    Stopif((Base64StringLength % 4) == 1,
           return 0xffffffff,
           "Bad Base64StringLength (should be padded)");

    // NOTE(brendan): length needed to store AsciiString corresponding to
    // Base64String. Last element should be 0
    uint32 AsciiStringLength = (Base64StringLength/4)*3;
    if (Base64String[Base64StringLength - 1] == '=')
    {
        if (Base64String[Base64StringLength - 2] == '=')
        {
            AsciiStringLength -= 2;
        }
        else
        {
            AsciiStringLength -= 1;
        }
    }
    AsciiString[AsciiStringLength] = 0;
    // NOTE(brendan): translate CIPHER from base64 to base256 (ASCII)
    for (uint32 Base64StringIndex = 0, ByteIndex = 0;
         Base64StringIndex < Base64StringLength;
         ++Base64StringIndex)
    {
        // NOTE(brendan): Break early if last one or two Base64 digits were
        // '=' padding
        if (ByteIndex >= AsciiStringLength)
        {
            break;
        }
        // NOTE(brendan): uint8 used so that we shift out bits we don't want
        uint8 Base64Digit = Base64ToUInt(Base64String[Base64StringIndex]);
        switch (Base64StringIndex % 4)
        {
            case 0:
            {
                AsciiString[ByteIndex] = Base64Digit << 2;
                break;
            }
            case 1:
            {
                AsciiString[ByteIndex] |= Base64Digit >> 4;
                AsciiString[ByteIndex + 1] = Base64Digit << 4;
                ++ByteIndex;
                break;
            }
            case 2:
            {
                AsciiString[ByteIndex] |= Base64Digit >> 2;
                AsciiString[ByteIndex + 1] = Base64Digit << 6;
                ++ByteIndex;
                break;
            }
            case 3:
            {
                AsciiString[ByteIndex] |= Base64Digit;
                ++ByteIndex;
                break;
            }
        }
    }
    return AsciiStringLength;
}

// NOTE(brendan): OUTPUT: OutHex[] array of hex values corresponding to input
// string.  INPUT: String[], Length of String
internal void
StringToHex(uint8 OutHex[], uint8 String[], uint32 StringLength)
{
    for (uint32 StringIndex = 0;
         StringIndex < StringLength;
         ++StringIndex)
    {
        sprintf((char *)(OutHex + 2*StringIndex), "%.2x", *(String + StringIndex));
    }
}

// NOTE(brendan): swap the characters S and T (xor trick)
internal void
Swap(uint8 *S, uint8 *T)
{
    *S ^= *T;
    *T ^= *S;
    *S ^= *T;
}

// NOTE(brendan): reverses string String and returns pointer to start of String;
// side-effects
internal uint8 *
ReverseString(uint8 *String)
{
    uint32 StringLength = strlen((char *)String);
    for (uint32 StringIndex = 0;
         StringIndex < StringLength/2;
         ++StringIndex)
    {
        Swap(String + StringIndex, String + (StringLength - 1) - StringIndex);
    }
    return String;
}

inline uint32
ByteSwap32(uint32 Word)
{
    uint32 Result = (Word << 24) | ((Word & 0xff00) << 8) |
                    ((Word & 0xff0000) >> 8) | (Word >> 24);
    return Result;
}

#endif /* CRYPT_HELPER_H */
