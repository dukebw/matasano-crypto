/* ========================================================================
   File: helper.cpp
   Date: Apr. 15/15
   Revision: 1
   Creator: Brendan Duke
   Notice: (C) Copyright 2015 by BRD Inc. All Rights Reserved.
   ======================================================================== */

#include "helper.h"

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

