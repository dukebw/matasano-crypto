/* ========================================================================
   File: hex_to_base64.cpp
   Date: Apr.13/15
   Revision: 1
   Creator: Brendan Duke
   Notice: (C) Copyright 2015 by BRD Inc. All Rights Reserved.
   ======================================================================== */

#include "stopif.h"
#include <stdio.h>
#include <ctype.h>
#include <math.h>
#include <string.h>

#define MAXLINE 512

// NOTE(brendan): swap the characters s and t (xor trick)
void Swap(char *s, char *t) {
    *s ^= *t;
    *t ^= *s;
    *s ^= *t;
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

// NOTE(brendan): INPUT: integer between 0 and 63 OUTPUT: base64 digit
char IntegerToBase64(int Value)
{
    Stopif((Value > 63) || (Value < 0), return -1,
           "Bad value passed to IntegerToBase64");
    if (Value < 26) {
        return 'A' + Value;
    }
    else if (Value < 52) {
        return 'a' + Value - 26;
    }
    else if (Value < 62) {
        return '0' + Value - 52;
    }
    else if (Value == 62) {
        return '+';
    }
    else {
        return '/';
    }
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

// NOTE(brendan): INPUT: base and exponent. OUTPUT: base^exponent
int IntegerPower(int Base, int Exponent)
{
    int Result = 1;
    while (Exponent) {
        if (Exponent & 1) {
            Result *= Base;
        }
        Exponent >>= 1;
        Base *= Base;
    }
    return Result;
}

int main(int argc, char **argv)
{
    char Base64String[MAXLINE];
    int Base64StringIndex = 0;
    if (argc > 1) {
        char *Base16String = ReverseString(argv[1]);
        while (*Base16String != '\0') {
            int ByteValue = 0;
            for (int ByteIndex = 0;
                 (ByteIndex < 3) && (*Base16String != '\0');
                 ++Base16String, ++ByteIndex) {
                ByteValue += IntegerPower(16, ByteIndex)*
                             Base16ToInteger(*Base16String);
            }
            Base64String[Base64StringIndex++] =
                IntegerToBase64(ByteValue & 0x3f);
            Base64String[Base64StringIndex++] =
                IntegerToBase64(ByteValue >> 6);
        }
        Base64String[Base64StringIndex] = '\0';
        ReverseString(Base64String);
        char *Base64StringNoZeros;
        for (Base64StringNoZeros = Base64String;
             *Base64StringNoZeros == 'A';
             ++Base64StringNoZeros);
        printf("%s\n", *Base64StringNoZeros ? Base64StringNoZeros : "A");
    }
}
