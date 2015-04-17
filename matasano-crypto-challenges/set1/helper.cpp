/* ========================================================================
   File: helper.cpp
   Date: Apr. 15/15
   Revision: 1
   Creator: Brendan Duke
   Notice: (C) Copyright 2015 by BRD Inc. All Rights Reserved.
   ======================================================================== */

#include "helper.h"

// ----------------------------------------------------------------------------
// Local functions
// ----------------------------------------------------------------------------

// NOTE(brendan): INPUT: string OUTPUT: score of string, based on frequencies
// of letters (score is sum of percentages of appearance)
internal uint32
ScoreString(char *DecodedString, uint32 Length)
{
    local_persist real32 Frequency[] = {
        8.12, 1.49, 2.71, 4.32, 12.02, 2.30, 2.03, 5.92, 7.31, 0.10, 0.69,
        3.98, 2.61, 6.95, 7.68, 1.82, 0.11, 6.02, 6.28, 9.10, 2.88, 1.11,
        2.09, 0.17, 2.11, 0.07
    };
    real32 ResultScore = 0.0f;
    for (uint32 CharIndex = 0; CharIndex < Length; ++CharIndex) {
        char UpperChar = toupper(DecodedString[CharIndex]);
        if (('A' <= UpperChar) && (UpperChar <= 'Z')) {
            ResultScore += Frequency[UpperChar - 'A'];
        }
        else if (UpperChar == ' ') {
            ResultScore += 16.67f;
        }
    }
    return ResultScore;
}

internal void
CreateKey(char *Key, uint32 ByteCipher, uint32 Length)
{
    for (uint32 KeyIndex = 0; KeyIndex < Length - 1; KeyIndex += 2) {
        sprintf(Key + KeyIndex, "%.2x", ByteCipher);
    }
}

// ----------------------------------------------------------------------------
// Access functions
// ----------------------------------------------------------------------------

// NOTE(brendan): swap the characters s and t (xor trick)
void Swap(char *s, char *t) {
    *s ^= *t;
    *t ^= *s;
    *s ^= *t;
}

// NOTE(brendan): INPUT: hex character. OUTPUT: integer value of hex character
int Base16ToInteger(char Value)
{
    Value = tolower(Value);
    if ((Value >= 'a') && (Value <= 'f')) {
        return 10 + Value - 'a';
    }
    else if ((Value >= '0') && (Value <= '9')) {
        return Value - '0';
    }
    else {
        Stopif(true, return -1, "Bad char passed to Base16ToInteger");
    }
}

// NOTE(brendan): reverses string s and returns pointer to start of s;
// side-effects
char *ReverseString(char *s) {
    int StringLength = strlen(s);
    for (int i = 0; i < StringLength/2; ++i) {
        Swap(s + i, s + (StringLength - 1) - i);
    }
    return s;
}

// NOTE(brendan): INPUT: output char array, two input hex char arrays, all of
// same length. OUTPUT: output char array gets the result of XORing the
// two input char arrays
void XORStrings(char *Result, char *StringA, char *StringB, uint32 Length)
{
    char TempString[2];
    while (*StringA !='\0') {
        uint32 HexDigitA = Base16ToInteger(*(StringA++));
        uint32 HexDigitB = Base16ToInteger(*(StringB++));
        uint32 DigitsXORed = (HexDigitA ^ HexDigitB);
        sprintf(TempString, "%.1x", DigitsXORed);
        *Result++ = TempString[0];
    }
    // NOTE(brendan): null-terminate the string
    *Result = 0;
}

// TODO(brendan): write own integer -> hex function? To avoid sprintf entirely
// NOTE(brendan): INPUT: output string, hex-encoded string. OUTPUT: string
// of characters
void DecodeHexString(char *Result, char *HexString, uint32 Length)
{
    char TempString[2];
    for (uint32 ResultIndex = 0; ResultIndex < Length - 1; ResultIndex += 2) {
        sprintf(TempString, "%c",
                16*Base16ToInteger(HexString[ResultIndex]) +
                Base16ToInteger(HexString[ResultIndex + 1]));
        *Result++ = TempString[0];
    }
    *Result = 0;
}

// NOTE(brendan): INPUT: Ciphertext, length of ciphertext.
// OUTPUT: string with max score based on frequency analysis, and from trying
// all byte ciphers
void ByteCipherDecodeString(char *DecodedString, char *Ciphertext,
                            uint32 CipherLength)
{
    uint32 DecodedStringLength = CipherLength/2 + 1;
    char Key[CipherLength + 1];
    // NOTE(brendan): decrypt
    real32 MaxScore = 0.0f;
    uint32 MaxCipher = 0;
    char XORResult[CipherLength + 1];
    for (uint32 ByteCipher = 0; ByteCipher < 256; ++ByteCipher) {
        CreateKey(Key, ByteCipher, CipherLength);
        XORStrings(XORResult, Key, Ciphertext, CipherLength);
        DecodeHexString(DecodedString, XORResult, CipherLength);
        real32 Score = ScoreString(DecodedString, DecodedStringLength - 1);
        if (Score > MaxScore) {
            MaxScore = Score;
            MaxCipher = ByteCipher;
        }
    }
    CreateKey(Key, MaxCipher, CipherLength);
    XORStrings(XORResult, Key, Ciphertext, CipherLength);
    DecodeHexString(DecodedString, XORResult, CipherLength);
}
