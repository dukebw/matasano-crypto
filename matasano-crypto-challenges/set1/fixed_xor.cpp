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
        uint32 InputBufferLength = strlen(Base16StringA);
        char FixedXORResult[InputBufferLength + 1];
        Stopif(InputBufferLength != strlen(Base16StringB),
               return -1, "Strings not of equal length.\n");
        char *pResult = FixedXORResult;
        while (*Base16StringA !='\0') {
            uint32 HexDigitA = Base16ToInteger(*(Base16StringA++));
            uint32 HexDigitB = Base16ToInteger(*(Base16StringB++));
            sprintf(pResult++, "%x", (HexDigitA ^ HexDigitB));
        }
        // NOTE(brendan): null-terminate the string
        *pResult = 0;
        printf("%s\n", FixedXORResult);
    }
}
