/* ========================================================================
   File: hex_to_base64.cpp
   Date: Apr.13/15
   Revision: 1
   Creator: Brendan Duke
   Notice: (C) Copyright 2015 by BRD Inc. All Rights Reserved.
   ======================================================================== */

#include "helper.h"

#define MAXLINE 512

// NOTE(brendan): INPUT: integer between 0 and 63 OUTPUT: base64 digit
internal char
IntegerToBase64(int Value)
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

// NOTE(brendan): INPUT: base and exponent. OUTPUT: base^exponent
internal int IntegerPower(int Base, int Exponent)
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
