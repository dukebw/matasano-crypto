/* ========================================================================
   File: fixed_xor.cpp
   Date: Apr. 15/15
   Revision: 1
   Creator: Brendan Duke
   Notice: (C) Copyright 2015 by BRD Inc. All Rights Reserved.
   ======================================================================== */

#include "helper.h"

int main(int argc, char **argv)
{
    if (argc > 2) {
        char *Base16StringA = argv[1];
        char *Base16StringB = argv[2];
        uint32 Length = strlen(Base16StringA);
        Stopif(Length != strlen(Base16StringB), return -1,
               "Strings not of equal length.\n");
        uint32 InputBufferLength = strlen(Base16StringA);
        char FixedXORResult[InputBufferLength + 1];
        XORStrings(FixedXORResult, Base16StringA, Base16StringB, Length);
        printf("%s\n", FixedXORResult);
    }
}
