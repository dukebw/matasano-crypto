/* ========================================================================
File: repeating_key_xor.cpp
Date: Apr. 24/15
Revision: 1
Creator: Brendan Duke
Notice: (C) Copyright 2015 by BRD Inc. All Rights Reserved.
======================================================================== */

#include "helper.h"

#define MAXLEN 1024

// NOTE(brendan): INPUT: Message, Length of message. OUTPUT: Result string.
// NOTE(brendan): Length is not including null character at end of string
internal void
EncryptMessage(char *ResultCipher, char *Message, uint32 Length)
{
    char KeyFragment[] = "IEC";
    char Key[Length + 1];
    for (uint32 KeyIndex = 0; KeyIndex < Length; KeyIndex += 2) {
        sprintf(Key + KeyIndex, "%.2x", KeyFragment[KeyIndex % 3]);
    }
    XORStrings(ResultCipher, Message, Key, Length);
}

int main(int argc, char **argv)
{
    if (argc > 1) {
        char Message[MAXLEN];
        FILE *infile = fopen(argv[1], "r");
        Stopif(infile == 0, "Couldn't open file %s", argv[1]);
        uint32 MessageLength = fread(Message, sizeof(char),
                                     MAXLEN, infile);
        uint32 HexMessageLength = 2*MessageLength;
        char HexMessage[HexMessageLength + 1];
        StringToHex(HexMessage, Message, MessageLength);

        char ResultCipher[HexMessageLength + 1];
        EncryptMessage(ResultCipher, HexMessage, HexMessageLength);
        printf("%s\n", ResultCipher);
        fclose(infile);
    }
}
