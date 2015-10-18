/* ========================================================================
File: sha_1_cyclic.cpp
Date: May 23/15
Revision: 1
Creator: Brendan Duke
Notice: (C) Copyright 2015 by BRD Inc. All Rights Reserved.
======================================================================== */

#include "crypt_helper.h"

#define MASK 0xf

inline uint32
Ch(uint32 X, uint32 Y, uint32 Z)
{
    uint32 Result = (X & Y) ^ (~X & Z);
    return Result;
}

inline uint32
Maj(uint32 X, uint32 Y, uint32 Z)
{
    uint32 Result = (X & Y) ^ (X & Z) ^ (Y & Z);
    return Result;
}

inline uint32
Parity(uint32 X, uint32 Y, uint32 Z)
{
    uint32 Result = X ^ Y ^ Z;
    return Result;
}

// NOTE(brendan): 32 bit words
inline uint32
RotateLeft(uint32 Word, uint32 ShiftAmount)
{
    uint32 Result = (Word << ShiftAmount) | (Word >> (32 - ShiftAmount));
    return Result;
}

// NOTE(brendan): SHA-1: INPUT: Message M such that |M| <= 2^64
// OUTPUT: A 160-bit hash (message digest) of the message
int main()
{
    char *Message = getenv("MESSAGE");
    Stopif(!Message, "No MESSAGE env variable");
    uint64 MessageLength = strlen(Message);
    // NOTE(brendan): ensure message is less than 2^64 bits long
    // TODO(brendan): only catches bad message length when message length in
    // bytes can be help in a uint64; fix
    Stopif(MessageLength >= pow(2, 61), "Input too long");

    // NOTE(brendan): We're assuming that the message comes in byte-sized
    // chunks
    uint64 BitsMessageLength = 8*MessageLength;
    uint32 PaddingBitsCount;
    // NOTE(brendan): Message length in bits mod 512
    uint32 BitsMessageRemainder = (BitsMessageLength + 1) % 512;
    if (BitsMessageRemainder > 448) {
        PaddingBitsCount = 960 - BitsMessageRemainder;
    } else {
        PaddingBitsCount = 448 - BitsMessageRemainder;
    }
    // NOTE(brendan): PaddedMessageLength will always be a multiple of 512,
    // and hence divisible by 32
    uint64 PaddedMessageLength = (BitsMessageLength + 1 +
                                  PaddingBitsCount + 64)/32;
    uint32 PaddedMessage[PaddedMessageLength];
    memset(PaddedMessage, 0, PaddedMessageLength*sizeof(PaddedMessage[0]));

    // TODO(brendan): faster to hash blocks as we read them in?
    uint32 PaddedMessageIndex = 0;
    for (uint32 ByteMessageIndex = 0;
          ByteMessageIndex < MessageLength;
          ++ByteMessageIndex) {
        // NOTE(brendan): ^ 3 hack to change endianness to little
        uint32 ShiftAmount = 8*((ByteMessageIndex % 4) ^ 3);
        PaddedMessage[PaddedMessageIndex] |= Message[ByteMessageIndex] <<
                                             ShiftAmount;
        if ((ByteMessageIndex % 4) == 3) {
            ++PaddedMessageIndex;
        }
    }

    uint32 MessageLengthMod4 = MessageLength % 4;
    PaddedMessage[PaddedMessageIndex] |= 0x80 << 8*(MessageLengthMod4 ^ 3);

    // NOTE(brendan): append 64-bit block equal to MessageLength in binary
    // NOTE(brendan): two 32-bit blocks ordered big endian
    PaddedMessage[PaddedMessageLength - 1] = BitsMessageLength & 0xffffffff;
    PaddedMessage[PaddedMessageLength - 2] = BitsMessageLength >> 32;

    uint32 SHA1Constants[] = {0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6};

    // NOTE(brendan): setting initial hash value
    uint32 HashValue[] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,
        0xc3d2e1f0};

    // NOTE(brendan): parse into BlockCount 512-bit blocks
    // M(1),...,M(BlockCount) expressed as 16 32-bit words M(i)_0,...,M(i)_15
    uint32 WordsPerBlock = 16;
    uint32 BlockCount = PaddedMessageLength/WordsPerBlock;

    uint32 Iterations = 80;
    uint32 MessageSchedSize = 16;
    uint32 MessageSchedule[MessageSchedSize]; 

    // NOTE(brendan): working variables a, b, c, d, e
    uint32 WorkingVars[5];
    for (uint32 BlockIndex = 0; BlockIndex < BlockCount; ++BlockIndex) {
        for (uint32 MessageSchedIndex = 0;
             MessageSchedIndex < MessageSchedSize;
             ++MessageSchedIndex) {
            MessageSchedule[MessageSchedIndex] =
                PaddedMessage[BlockIndex*WordsPerBlock + MessageSchedIndex];
        }

        for (uint32 HashIndex = 0; HashIndex < 5; ++HashIndex) {
            WorkingVars[HashIndex] = HashValue[HashIndex];
        }

        uint32 (*f_t[])(uint32, uint32, uint32) = {Ch, Parity, Maj, Parity};
        for (uint32 IterationIndex = 0;
             IterationIndex < Iterations;
             ++IterationIndex) {
            uint32 S = IterationIndex & MASK;

            if (IterationIndex >= 16) {
                uint32 XORedWords = MessageSchedule[(S + 13) & MASK] ^
                                    MessageSchedule[(S + 8) & MASK] ^
                                    MessageSchedule[(S + 2) & MASK] ^
                                    MessageSchedule[S];
                MessageSchedule[S] = RotateLeft(XORedWords, 1);

            }

            uint32 Selector = IterationIndex/20;
            // TODO(brendan): debug this step...
            uint32 T = RotateLeft(WorkingVars[0], 5) +
                       f_t[Selector](WorkingVars[1], WorkingVars[2],
                                     WorkingVars[3]) +
                       WorkingVars[4] + SHA1Constants[Selector] +
                       MessageSchedule[S];
            WorkingVars[4] = WorkingVars[3];
            WorkingVars[3] = WorkingVars[2];
            WorkingVars[2] = RotateLeft(WorkingVars[1], 30);
            WorkingVars[1] = WorkingVars[0];
            WorkingVars[0] = T;
        }
        // TODO(brendan): Swap to Big Endian at the end
        for (uint32 HashIndex = 0; HashIndex < 5; ++HashIndex) {
            HashValue[HashIndex] = HashValue[HashIndex] +
                                   WorkingVars[HashIndex];
        }
    }
    printf("%x %x %x %x %x\n", HashValue[0], HashValue[1], HashValue[2],
            HashValue[3], HashValue[4]);
}
