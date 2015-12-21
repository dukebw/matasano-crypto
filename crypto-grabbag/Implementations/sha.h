#include "allheads.h"

#define MASK 0xf
#define WORKING_VARS_COUNT 5
#define SHA_1_HASH_LENGTH_BYTES 20
#define BITS_IN_DWORD 64
#define BITS_IN_WORD 32
#define BITS_IN_BYTE 8

internal inline u32
ByteSwap32(u32 Word)
{
	u32 Result = ((Word << 24) | ((Word & 0xFF00) << 8) | ((Word & 0xFF0000) >> 8) | (Word >> 24));
    return Result;
}

const u32
SHA_1_CONSTANTS[] =
{
	0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
};

internal inline u32
Ch(u32 X, u32 Y, u32 Z)
{
    u32 Result = (X & Y) ^ (~X & Z);
    return Result;
}

internal inline u32
Maj(u32 X, u32 Y, u32 Z)
{
    u32 Result = (X & Y) ^ (X & Z) ^ (Y & Z);
    return Result;
}

internal inline u32
Parity(u32 X, u32 Y, u32 Z)
{
    u32 Result = X ^ Y ^ Z;
    return Result;
}

// NOTE(brendan): 32 bit words
internal inline u32
RotateLeft(u32 Word, u32 ShiftAmount)
{
    u32 Result = (Word << ShiftAmount) | (Word >> (32 - ShiftAmount));
    return Result;
}

internal u32
PadSha1(u32 *PaddedMessage, u32 MessageLength, u32 HashedInitialLength)
{
	Stopif(PaddedMessage == 0, "Null input to PadSha1");

    // NOTE(brendan): We're assuming that the message comes in byte-sized
    // chunks
    u64 BitsMessageLength = BITS_IN_BYTE*MessageLength;
    u32 ZeroPaddingBitsCount;
    // NOTE(brendan): Message length in bits mod 512
    u32 BitsMessageRemainder = (BitsMessageLength + 1) % 512;
    if (BitsMessageRemainder > 448)
	{
        ZeroPaddingBitsCount = 960 - BitsMessageRemainder;
    }
	else
	{
        ZeroPaddingBitsCount = 448 - BitsMessageRemainder;
    }
    // NOTE(brendan): PaddedMessageLength will always be a multiple of 512,
    // and hence divisible by 32
	u32 ExtraBitsCount = 1 + ZeroPaddingBitsCount + 64;
    u32 PaddedMessageLength = (BitsMessageLength + ExtraBitsCount)/BITS_IN_WORD;
    memset((u8 *)PaddedMessage + MessageLength, 0, (ExtraBitsCount/BITS_IN_BYTE));

    *((u8 *)PaddedMessage + MessageLength) = 0x80;

    // NOTE(brendan): append 64-bit block equal to MessageLength in binary
    // NOTE(brendan): two 32-bit blocks ordered big endian
	u64 TotalBitsMessageLength = BitsMessageLength + (BITS_IN_BYTE*HashedInitialLength);
    PaddedMessage[PaddedMessageLength - 1] = TotalBitsMessageLength & 0xffffffff;
    PaddedMessage[PaddedMessageLength - 2] = TotalBitsMessageLength >> 32;

	return PaddedMessageLength;
}

const u32
SHA_1_HASH_INITIAL_VALUES[] =
{
	0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
};

internal void
Sha1InitialValues(u8 *Hash, u8 *Message, u32 MessageLength, u8 *HashInitialValues, u32 HashInitialLength)
{
    Stopif((Hash == 0) || (Message == 0) || (HashInitialValues == 0), "Null input to Sha1InitialValues");

    // NOTE(brendan): ensure message is less than 2^64 bits long
    // TODO(brendan): only catches bad message length when message length in
    // bytes can be held in a u64; fix
    Stopif(MessageLength >= pow(2, 61), "Input too long");

    u32 PaddedMessage[MessageLength + 1024];

	memcpy(PaddedMessage, Message, MessageLength);

	u32 PaddedMessageLengthWords = PadSha1(PaddedMessage, MessageLength, HashInitialLength);

	for (u32 PaddedMsgWordIndex = 0;
		 PaddedMsgWordIndex < (PaddedMessageLengthWords - 2);
		 ++PaddedMsgWordIndex)
	{
		PaddedMessage[PaddedMsgWordIndex] = ByteSwap32(PaddedMessage[PaddedMsgWordIndex]);
	}

	u32 HashValue[ARRAY_LENGTH(SHA_1_HASH_INITIAL_VALUES)];
	memcpy(HashValue, HashInitialValues, sizeof(SHA_1_HASH_INITIAL_VALUES));

    // NOTE(brendan): parse into BlockCount 512-bit blocks
    // M(1),...,M(BlockCount) expressed as 16 32-bit words M(i)_0,...,M(i)_15
    u32 WordsPerBlock = 16;
    u32 BlockCount = PaddedMessageLengthWords/WordsPerBlock;

    u32 Iterations = 80;
    u32 MessageSchedSize = 16;
    u32 MessageSchedule[MessageSchedSize]; 

	// NOTE(brendan): working variables a, b, c, d, e
	u32 WorkingVars[WORKING_VARS_COUNT];
	for (u32 BlockIndex = 0;
		 BlockIndex < BlockCount;
		 ++BlockIndex)
	{
		for (u32 MessageSchedIndex = 0;
			 MessageSchedIndex < MessageSchedSize;
			 ++MessageSchedIndex)
		{
			MessageSchedule[MessageSchedIndex] = PaddedMessage[BlockIndex*WordsPerBlock + MessageSchedIndex];
		}

        for (u32 HashIndex = 0;
			 HashIndex < WORKING_VARS_COUNT;
			 ++HashIndex)
		{
            WorkingVars[HashIndex] = HashValue[HashIndex];
        }

        u32 (*f_t[])(u32, u32, u32) =
		{
			Ch, Parity, Maj, Parity
		};

        for (u32 IterationIndex = 0;
             IterationIndex < Iterations;
             ++IterationIndex)
		{
            u32 S = IterationIndex & MASK;

            if (IterationIndex >= 16)
			{
                u32 XORedWords = (MessageSchedule[(S + 13) & MASK] ^
								  MessageSchedule[(S + 8) & MASK] ^
								  MessageSchedule[(S + 2) & MASK] ^
								  MessageSchedule[S]);
                MessageSchedule[S] = RotateLeft(XORedWords, 1);

            }

            u32 Selector = IterationIndex/20;
            // TODO(brendan): debug this step...
            u32 T = (RotateLeft(WorkingVars[0], 5) + f_t[Selector](WorkingVars[1], WorkingVars[2], WorkingVars[3]) +
					 WorkingVars[4] + SHA_1_CONSTANTS[Selector] + MessageSchedule[S]);
            WorkingVars[4] = WorkingVars[3];
            WorkingVars[3] = WorkingVars[2];
            WorkingVars[2] = RotateLeft(WorkingVars[1], 30);
            WorkingVars[1] = WorkingVars[0];
            WorkingVars[0] = T;
        }

        for (u32 HashIndex = 0;
			 HashIndex < WORKING_VARS_COUNT;
			 ++HashIndex)
		{
            HashValue[HashIndex] = HashValue[HashIndex] + WorkingVars[HashIndex];
        }
    }

	for (u32 HashIndex = 0;
		 HashIndex < WORKING_VARS_COUNT;
		 ++HashIndex)
	{
		*((u32 *)Hash + HashIndex) = ByteSwap32(HashValue[HashIndex]);
	}
}

// NOTE(brendan): SHA-1: INPUT: Message M such that |M| <= 2^64
// OUTPUT: A 160-bit hash (message digest) of the message
internal void
Sha1(u8 *Hash, u8 *Message, u32 MessageLength)
{
	// Param checking done in inner function -- no need to check
	Sha1InitialValues(Hash, Message, MessageLength, (u8 *)SHA_1_HASH_INITIAL_VALUES, 0);
}
