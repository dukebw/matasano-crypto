/* ========================================================================
   File: detect_single_char_xor.cpp
   Date: Apr. 18/15
   Revision: 1
   Creator: Brendan Duke
   Notice: (C) Copyright 2015 by BRD Inc. All Rights Reserved.
   ======================================================================== */

#include "helper.h"

#define MAXLEN 1024

int main()
{
    char Ciphertext[MAXLEN];
    int CipherLength;
    real32 MinScore = INFINITY;
    char MinScoreString[MAXLEN];
    char ResultString[MAXLEN];
    while ((CipherLength = GetLine(Ciphertext, MAXLEN))) {
        real32 Score = ByteCipherInHexDecode(ResultString, Ciphertext,
                                              CipherLength);
        if (Score < MinScore) {
            strncpy(MinScoreString, ResultString, CipherLength/2 + 1);
            MinScore = Score;
        }
    }
    printf("%s", MinScoreString);
}
