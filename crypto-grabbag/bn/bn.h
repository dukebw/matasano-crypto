#ifndef BN_H
#define BN_H

#include "crypt_helper.h"

#define BIG_NUM_MAX_WORDS 32

// TODO(brendan): support for negative numbers
typedef struct {
    uint32 Size;
    uint64 Buffer[BIG_NUM_MAX_WORDS];
} big_number;

internal big_number *
BigNumNew()
{
    big_number *Result;
    Result = malloc(sizeof(*Result));
    memset(Result, 0, sizeof(*Result));
    return Result;
}

// NOTE(brendan): returns 1 for carry, 0 otherwise
internal uint32
BigNumAddMultiPrecision(big_number *Output, big_number *A, big_number *B)
{
    uint32 MaxSize = (A->Size > B->Size) ? A->Size : B->Size;

    Stopif((MaxSize > BIG_NUM_MAX_WORDS), return -1, "Bad size");

    uint32 Carry = 0;
    Output->Buffer[0] = A->Buffer[0] + B->Buffer[0];
    if (Output->Buffer[0] < A->Buffer[0]) {
        Carry = 1;
    }
    // TODO(brendan): use inline assembly adc to add with carry
    for (uint32 BufferIndex = 1; BufferIndex < MaxSize; ++BufferIndex) {
        if (Output->Buffer[BufferIndex - 1] < (A->Buffer[BufferIndex - 1] + Carry)) {
            Carry = 1;
        } else {
            Carry = 0;
        }
        Output->Buffer[BufferIndex] = A->Buffer[BufferIndex] + B->Buffer[BufferIndex] + Carry;
    }

    if (Carry && (MaxSize < BIG_NUM_MAX_WORDS)) {
        Carry = 0;
        Output->Buffer[MaxSize] = 1;
        Output->Size = MaxSize + 1;
    } else {
        Output->Size = MaxSize;
    }

    return Carry;
}

#endif /* BN_H */
