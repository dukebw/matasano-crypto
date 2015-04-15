#ifndef HELPER_H
#define HELPER_H

#include "stopif.h"
#include <stdio.h>
#include <ctype.h>
#include <math.h>
#include <string.h>
#include <stdint.h>

#define internal static
#define local_persist static
#define global_variable static

typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;

typedef int8_t int8;
typedef int16_t int16;
typedef int32_t int32;
typedef int64_t int64;
typedef int32 bool32;

typedef float real32;
typedef double real64;

// NOTE(brendan): swap the characters s and t (xor trick)
void Swap(char *s, char *t);

// NOTE(brendan): INPUT: hex character. OUTPUT: integer value of hex character
int Base16ToInteger(char Value);

// NOTE(brendan): reverses string s and returns pointer to start of s;
// side-effects
char *ReverseString(char *s);

#endif /* HELPER_H */
