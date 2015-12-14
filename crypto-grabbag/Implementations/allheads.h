#ifndef ALLHEADS_H
#define ALLHEADS_H

#include <stdbool.h>
#include <math.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>
#include "stopif.h"

#define internal static
#define local_persist static
#define global_variable static

#define ARRAY_LENGTH(array) (sizeof(array)/sizeof((array)[0]))

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef __uint128_t u128;

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;
typedef i32 b32;

typedef float r32;
typedef double r64;

#endif /* ALLHEADS_H */
