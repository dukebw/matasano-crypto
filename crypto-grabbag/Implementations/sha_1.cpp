/* ========================================================================
   File: sha_1.cpp
   Date: May 12/15
   Revision: 1
   Creator: Brendan Duke
   Notice: (C) Copyright 2015 by BRD Inc. All Rights Reserved.
   ======================================================================== */

#include "crypt_helper.h"

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

inline uint32
ByteSwap32(uint32 Word)
{
    uint32 Result = (Word << 24) | ((Word & 0xff00) << 8) |
                    ((Word & 0xff0000) >> 8) | (Word >> 24);
    return Result;
}

// NOTE(brendan): SHA-1: INPUT: Message M such that |M| <= 2^64
// OUTPUT: A 160-bit hash (message digest) of the message
int main()
{
    // NOTE(brendan): BIG ENDIAN
    char *Message = getenv("MESSAGE");
    Stopif(!Message, return -1, "No MESSAGE env variable");
    uint64 MessageLength = strlen(Message);
    // NOTE(brendan): ensure message is less than 2^64 bits long
    // TODO(brendan): only catches bad message length when message length in
    // bytes can be help in a uint64; fix
    Stopif(MessageLength >= pow(2, 61), return -1, "Input too long");

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

    uint32 PaddedMessageIndex = 0;
    for (uint32 ByteMessageIndex = 0;
         ByteMessageIndex < MessageLength;
         ++ByteMessageIndex) {
        uint32 ShiftAmount = 8*(ByteMessageIndex % 4);
        PaddedMessage[PaddedMessageIndex] |=
            Message[ByteMessageIndex] << ShiftAmount;
        if ((ByteMessageIndex % 4) == 3) {
            ++PaddedMessageIndex;
        }
    }

    uint32 MessageLengthMod4 = MessageLength % 4;
    if (MessageLengthMod4 == 0) {
        PaddedMessage[PaddedMessageIndex + 1] = 0x80000000;
    } else {
        PaddedMessage[PaddedMessageIndex] |= 0x80 << 8*MessageLengthMod4;
    }

    // NOTE(brendan): append 64-bit block equal to MessageLength in binary
    PaddedMessage[PaddedMessageLength - 1] = ByteSwap32(BitsMessageLength &
                                                        0xffffffff);
    PaddedMessage[PaddedMessageLength - 2] = ByteSwap32(BitsMessageLength >> 32);

    // NOTE(brendan): BIG ENDIAN! Little endian:
    // 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
    uint32 SHA1Constants[] = {0x9979825a, 0xa1ebd96e, 0xdcbc1b8f, 0xd6c162ca};

    // NOTE(brendan): setting initial hash value
    // NOTE(brendan): BIG ENDIAN! Little endian:
    // 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
    uint32 HashValue[] = {0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210,
                          0xf0e1d2c3};

    // NOTE(brendan): parse into BlockCount 512-bit blocks M(1),...,M(BlockCount)
    // expressed as 16 32-bit words M(i)_0,...,M(i)_15
    uint32 WordsPerBlock = 16;
    uint32 BlockCount = PaddedMessageLength/WordsPerBlock;

    uint32 MessageSchedSize = 80;
    uint32 MessageSchedule[MessageSchedSize]; 

    // NOTE(brendan): working variables a, b, c, d, e
    uint32 WorkingVars[5];
    for (uint32 HashIndex = 0; HashIndex < 5; ++HashIndex) {
        WorkingVars[HashIndex] = HashValue[HashIndex];
    }

    for (uint32 BlockIndex = 0; BlockIndex < BlockCount; ++BlockIndex) {
        for (uint32 MessageSchedIndex = 0;
             MessageSchedIndex < MessageSchedSize;
             ++MessageSchedIndex) {
            if (MessageSchedIndex < WordsPerBlock) {
                MessageSchedule[MessageSchedIndex] =
                    PaddedMessage[BlockIndex*WordsPerBlock + MessageSchedIndex];
            } else {
                uint32 XORedWords = MessageSchedule[MessageSchedIndex - 3] ^
                                    MessageSchedule[MessageSchedIndex - 8] ^
                                    MessageSchedule[MessageSchedIndex - 14] ^
                                    MessageSchedule[MessageSchedIndex - 16];
                MessageSchedule[MessageSchedIndex] = RotateLeft(XORedWords, 1);
            }
        }

        uint32 (*f_t[])(uint32, uint32, uint32) = {Ch, Parity, Maj, Parity};
        for (uint32 MessageSchedIndex = 0;
             MessageSchedIndex < MessageSchedSize;
             ++MessageSchedIndex) {
            uint32 Selector = MessageSchedIndex/20;
            // TODO(brendan): debug this step...
            uint32 T = ByteSwap32(RotateLeft(WorkingVars[0], 5)) +
                ByteSwap32(f_t[Selector](WorkingVars[1], WorkingVars[2],
                                         WorkingVars[3])) +
                ByteSwap32(WorkingVars[4]) +
                ByteSwap32(SHA1Constants[Selector]) +
                ByteSwap32(MessageSchedule[MessageSchedIndex]);
            T = ByteSwap32(T);
            WorkingVars[4] = WorkingVars[3];
            WorkingVars[3] = WorkingVars[2];
            WorkingVars[2] = RotateLeft(WorkingVars[1], 30);
            WorkingVars[1] = WorkingVars[0];
            WorkingVars[0] = T;
        }
        for (uint32 HashIndex = 0; HashIndex < 5; ++HashIndex) {
            HashValue[HashIndex] = ByteSwap32(HashValue[HashIndex]) +
                                   ByteSwap32(WorkingVars[HashIndex]);
        }
    }
    printf("%x %x %x %x %x\n", HashValue[0], HashValue[1], HashValue[2],
                               HashValue[3], HashValue[4]);
}
