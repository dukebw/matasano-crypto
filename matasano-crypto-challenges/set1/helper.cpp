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
internal real32
ScoreString(char *DecodedString, uint32 Length)
{
#define ENGLISH_LETTER_COUNT 26
    local_persist real32 ExpectedFrequency[] = {
        8.12, 1.49, 2.71, 4.32, 12.02, 2.30, 2.03, 5.92, 7.31, 0.10, 0.69,
        3.98, 2.61, 6.95, 7.68, 1.82, 0.11, 6.02, 6.28, 9.10, 2.88, 1.11,
        2.09, 0.17, 2.11, 0.07
    };
    uint32 LetterCount[ENGLISH_LETTER_COUNT] = {0};
    real32 ResultScore = 0.0f;
    for (uint32 CharIndex = 0; CharIndex < Length; ++CharIndex) {
        char UpperChar = toupper(DecodedString[CharIndex]);
        if (('A' <= UpperChar) && (UpperChar <= 'Z')) {
            ++LetterCount[UpperChar - 'A'];
        } else if (!isspace(UpperChar)) { // TODO(brendan): punctuation?
            ResultScore += 100.0f;
        }
    }
    for (uint32 LetterIndex = 0;
         LetterIndex < ENGLISH_LETTER_COUNT;
         ++LetterIndex) {
        ResultScore += fabs(ExpectedFrequency[LetterIndex] -
                            (real32)LetterCount[LetterIndex]/(real32)Length);
    }
    return ResultScore;
#undef ENGLISH_LETTER_COUNT
}

// NOTE(brendan): INPUT: a byte-cipher and a length for the key.
// OUTPUT: A key with the byte-cipher repeated across its length
internal void
CreateKey(char *Key, uint32 ByteCipher, uint32 Length)
{
    for (uint32 KeyIndex = 0; KeyIndex < Length - 1; KeyIndex += 2) {
        sprintf(Key + KeyIndex, "%.2x", ByteCipher);
    }
}

// NOTE(brendan): INPUT: a byte-cipher and a length for the key.
// OUTPUT: A key with the byte-cipher repeated across its length
inline void
CreateAsciiKey(char *Key, uint32 ByteCipher, uint32 Length)
{
    for (uint32 KeyIndex = 0; KeyIndex < Length; ++KeyIndex) {
        Key[KeyIndex] = ByteCipher;
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
    } else if ((Value >= '0') && (Value <= '9')) {
        return Value - '0';
    } else {
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

// NOTE(brendan): INPUT: output char array, two input ASCII char arrays, all of
// same length. OUTPUT: output char array gets the result of XORing the
// two input char arrays
inline void
XORAsciiStrings(char *Result, char *StringA, char *StringB, uint32 Length)
{
    for (uint32 StringIndex = 0; StringIndex < Length; ++StringIndex) {
        Result[StringIndex] = StringA[StringIndex] ^ StringB[StringIndex];
    }
}

// NOTE(brendan): INPUT: output char array, two input hex char arrays, all of
// same length. OUTPUT: output char array gets the result of XORing the
// two input char arrays
void XORStrings(char *Result, char *StringA, char *StringB, uint32 Length)
{
    // NOTE(brendan): null-terminate the string
    *(Result + Length) = 0;
    char TempString[2];
    for (uint32 StringIndex = 0; StringIndex < Length; ++StringIndex) {
        uint32 HexDigitA = Base16ToInteger(*(StringA + StringIndex));
        uint32 HexDigitB = Base16ToInteger(*(StringB + StringIndex));
        uint32 DigitsXORed = (HexDigitA ^ HexDigitB);
        sprintf(TempString, "%.1x", DigitsXORed);
        *(Result + StringIndex) = TempString[0];
    }
}

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

// NOTE(brendan): INPUT: Ciphertext in ASCII-256, length of ciphertext.
// OUTPUT: string with max score based on frequency analysis, and from trying
// all byte ciphers
uint8 ByteCipherAsciiDecode(char *DecodedString, char *Ciphertext,
                            uint32 CipherLength)
{
    char Key[CipherLength + 1];
    Key[CipherLength] = 0;
    // NOTE(brendan): decrypt
    real32 MinScore = INFINITY;
    uint32 MinCipher = 0;
    // TODO(brendan): calculate frequencies and subtract from expected
    // frequencies; maximize that value
    for (uint32 ByteCipher = 0; ByteCipher < 256; ++ByteCipher) {
        CreateAsciiKey(Key, ByteCipher, CipherLength);
        XORAsciiStrings(DecodedString, Key, Ciphertext, CipherLength);
        for (uint32 CipherIndex = 0;
             CipherIndex < CipherLength;
             ++CipherIndex) {
            DecodedString[CipherIndex] = Key[CipherIndex] ^
                                         Ciphertext[CipherIndex];
        }
        real32 Score = ScoreString(DecodedString, CipherLength);
        if (Score < MinScore) {
            MinScore = Score;
            MinCipher = ByteCipher;
        }
    }
    CreateAsciiKey(Key, MinCipher, CipherLength);
    XORAsciiStrings(DecodedString, Key, Ciphertext, CipherLength);
    return MinCipher;
}

// NOTE(brendan): INPUT: Ciphertext in hex, length of ciphertext.
// OUTPUT: string with max score based on frequency analysis, and from trying
// all byte ciphers
real32 ByteCipherInHexDecode(char *DecodedString, char *Ciphertext,
                             uint32 CipherLength)
{
    uint32 DecodedStringLength = CipherLength/2 + 1;
    char Key[CipherLength + 1];
    // NOTE(brendan): decrypt
    real32 MinScore = INFINITY;
    uint32 MinCipher = 0;
    char XORResult[CipherLength + 1];
    // TODO(brendan): calculate frequencies and subtract from expected
    // frequencies; maximize that value
    for (uint32 ByteCipher = 0; ByteCipher < 256; ++ByteCipher) {
        CreateKey(Key, ByteCipher, CipherLength);
        XORStrings(XORResult, Key, Ciphertext, CipherLength);
        DecodeHexString(DecodedString, XORResult, CipherLength);
        real32 Score = ScoreString(DecodedString, DecodedStringLength - 1);
        if (Score < MinScore) {
            MinScore = Score;
            MinCipher = ByteCipher;
        }
    }
    CreateKey(Key, MinCipher, CipherLength);
    XORStrings(XORResult, Key, Ciphertext, CipherLength);
    DecodeHexString(DecodedString, XORResult, CipherLength);
    return MinScore;
}

// NOTE(brendan): read a line into s; return length
int GetLine(char OutString[], int Limit) {
    int NextChar;

    char *Start = OutString;
    while ((Limit-- > 0) && ((NextChar = getchar()) != EOF) &&
          (NextChar != '\n')) {
        *OutString++ = NextChar;
    }
    if (NextChar == '\n') {
        *OutString++ = NextChar;
    }
    *OutString = '\0';
    return (OutString - Start);
}

// NOTE(brendan): OUTPUT: OutHex[] array of hex values corresponding to input
// string.  INPUT: String[], Length of String
void StringToHex(char OutHex[], char String[], uint32 StringLength)
{
    for (uint32 StringIndex = 0; StringIndex < StringLength; ++StringIndex) {
        sprintf(OutHex + 2*StringIndex, "%.2x", *(String + StringIndex));
    }
}
