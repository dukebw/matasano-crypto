#ifndef CRYPT_HELPER_H
#define CRYPT_HELPER_H

#include "allheads.h"
#include "aes.h"
#include "sha.h"
#include "min_unit.h"
#include "compile_assert.h"

CASSERT(RAND_MAX <= UINT32_MAX, crypt_helper_h);

typedef struct timespec timespec;

#pragma GCC diagnostic ignored "-Wunused-function"

#define INVALID_CODE_PATH Stopif(true, "Invalid code path!")

#define STR_LEN(String) (ARRAY_LENGTH(String) - 1)

#define ALPHABET_SIZE 26

#define EXPECTED_SPACE_FREQUENCY 0.15f
#define EXPECTED_PUNCT_FREQUENCY 0.025f

#define BITMASK_MOD_DWORD(Bits) (((u64)1 << ((Bits) % BITS_IN_DWORD)) - 1)

#define BIT_COUNT_DWORD(DWordValue) (BITS_IN_DWORD - __builtin_clzl(DWordValue))

#define MASK_64BIT 0xFFFFFFFFFFFFFFFFull

#define SHA_1_KEYED_MAC_MAX_MSG_SIZE 256

#define ONE_THOUSAND 1000
#define ONE_MILLION (ONE_THOUSAND*ONE_THOUSAND)
#define ONE_BILLION (ONE_THOUSAND*ONE_MILLION)

#define SIZE_1KB 0x1000
#define SIZE_1MB (SIZE_1KB*SIZE_1KB)
#define SIZE_1GB (SIZE_1MB*SIZE_1KB)

#define IS_ODD(Value) ((Value) & 0x1)
#define IS_EVEN(Value) (!IS_ODD(Value))

#define MEMBER_SIZE(type, Member) sizeof(((type *)0)->Member)

const r32 EXPECTED_LETTER_FREQUENCY[] =
{
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094,
    0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929,
    0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.02361, 0.00150,
    0.01974, 0.00074
};

internal inline u64
MaskBitcount(u32 Bitcount)
{
    u64 Result = (1ull << Bitcount) - 1ull;
    return Result;
}

internal inline u32
Maximum(u32 A, u32 B)
{
    u32 Result;

    if (A > B)
    {
        Result = A;
    }
    else
    {
        Result = B;
    }

    return Result;
}

internal b32
AreVectorsEqual(void *A, void *B, u32 Length)
{
	Stopif((A == 0) || (B == 0), "Null input to AreVectorsEqual\n");
	u32 Result = true;
	u8 *AByteVec = (u8 *)A;
	u8 *BByteVec = (u8 *)B;
	for (u32 VectorIndex = 0;
		 VectorIndex < Length;
		 ++VectorIndex)
	{
		if (AByteVec[VectorIndex] != BByteVec[VectorIndex])
		{
			Result = false;
			break;
		}
	}
	return Result;
}

internal b32
AreVectorsEqualByteSwapped(u8 *A, u8 *B, u32 LengthBytes)
{
    Stopif((A == 0) || (B == 0), "Null input to AreVectorsEqualByteSwapped!\n");

    b32 Result = true;

    for (u32 BIndex = 0;
         BIndex < LengthBytes;
         ++BIndex)
    {
        if (A[LengthBytes - BIndex - 1] != B[BIndex])
        {
            Result = false;
            break;
        }
    }

    return Result;
}

// NOTE(brendan): INPUT: character to shift mod 26, shift amount (assumed to be
// in [0, 25]. OUTPUT: corresponding lower-case character, shifted mod 26
internal u32
ShiftChar(u32 ToShiftChar, u32 ShiftAmount)
{
    // TODO(brendan): more checking
    Stopif(!(((ToShiftChar <= 'Z') && (ToShiftChar >= 'A')) ||
             ((ToShiftChar <= 'z') && (ToShiftChar >= 'a'))),
           "Bad input char\n");
    u32 Result;
    u32 PreModChar = tolower(ToShiftChar) + ShiftAmount;
    if (PreModChar <= 'z')
    {
        Result = PreModChar;
    }
    else
    {
        Result = PreModChar - 26;
    }
    return Result;
}

// NOTE(brendan): INPUT: Cipher, its length and the length of the key.
// OUTPUT: the best shift amount (the shift amount that makes the Cipher
// closest to english-language letter frequency)
internal u32
GetBestShiftAmount(char *Cipher, u32 CipherLength, u32 KeyLength)
{
    u32 CharCounts[ALPHABET_SIZE] = {};
    u32 Result = 0;
    r32 BestShiftDelta = INFINITY;
 
    for (u32 ShiftAmount = 0; ShiftAmount < ALPHABET_SIZE; ++ShiftAmount)
    {
        for (u32 CipherIndex = 0;
             CipherIndex < CipherLength;
             CipherIndex += KeyLength)
        {
            u32 AlphabetOffset = ShiftChar(Cipher[CipherIndex], ShiftAmount) - 'a';
            ++CharCounts[AlphabetOffset];
        }
        r32 ShiftFrequencySum = 0.0f;
        for (u32 CharIndex = 0; CharIndex < ALPHABET_SIZE; ++CharIndex)
        {
            r32 KeyLetterFreq = (r32)CharCounts[CharIndex]/(r32)CipherLength;
            ShiftFrequencySum += KeyLetterFreq*EXPECTED_LETTER_FREQUENCY[CharIndex];
        }
        r32 ShiftDelta = fabs(ShiftFrequencySum - 0.065);
        if (ShiftDelta < BestShiftDelta)
        {
            Result = ShiftAmount;
            BestShiftDelta = ShiftDelta;
        }
        memset((void *)CharCounts, 0, ALPHABET_SIZE*sizeof(CharCounts[0]));
    }

    return Result;
}

// NOTE(brendan): INPUT: digit in base 64. OUTPUT: that digit translated to
// a u32, or -1 if the given char was not a valid base 64 digit.
internal u32
Base64ToUInt(u8 Base64Digit)
{
    if ((Base64Digit >= 'A') && (Base64Digit <= 'Z'))
    {
        return Base64Digit - 'A';
    }
    else if ((Base64Digit >= 'a') && (Base64Digit <= 'z'))
    {
        return Base64Digit - 'a' + 26;
    }
    else if ((Base64Digit >= '0') && (Base64Digit <= '9'))
    {
        return Base64Digit - '0' + 52;
    }
    else if (Base64Digit == '+')
    {
        return 62;
    }
    else if (Base64Digit == '/')
    {
        return 63;
    }
    Stopif(true, "Bad Base64Digit passed to Base64ToUint\n");
}

internal u32
Base64ToAscii(u8 *AsciiString, u8 *Base64String, u32 Base64StringLength)
{
	Stopif((AsciiString == 0) || (Base64String == 0), "Null input to Base64ToAscii\n");
	Stopif((Base64StringLength % 4) == 1, "Bad Base64StringLength (ends in 6 bits)\n");
	// TODO(bwd): fix so target can == source
	Stopif(AsciiString == Base64String, "Equal Source/Dest not supported yet in Base64ToAscii\n");

	// 10101010 1010_1010 1010_1010
	// 101010
    // NOTE(brendan): length needed to store AsciiString corresponding to
    // Base64String. Last element should be 0
	u32 AsciiStringLength = (Base64StringLength/4)*3;
    if (Base64String[Base64StringLength - 1] == '=')
    {
        if (Base64String[Base64StringLength - 2] == '=')
        {
            AsciiStringLength -= 2;
        }
        else
        {
            AsciiStringLength -= 1;
        }
    }
    AsciiString[AsciiStringLength] = 0;

    // NOTE(brendan): translate CIPHER from base64 to base256 (ASCII)
    for (u32 Base64StringIndex = 0, ByteIndex = 0;
         Base64StringIndex < Base64StringLength;
         ++Base64StringIndex)
    {
        // NOTE(brendan): Break early if last one or two Base64 digits were
        // '=' padding
        if (ByteIndex >= AsciiStringLength)
        {
            break;
        }
        // NOTE(brendan): u8 used so that we shift out bits we don't want
        u8 Base64Digit = Base64ToUInt(Base64String[Base64StringIndex]);
        switch (Base64StringIndex % 4)
        {
            case 0:
            {
                AsciiString[ByteIndex] = Base64Digit << 2;
                break;
            }
            case 1:
            {
                AsciiString[ByteIndex] |= Base64Digit >> 4;
                AsciiString[ByteIndex + 1] = Base64Digit << 4;
                ++ByteIndex;
                break;
            }
            case 2:
            {
                AsciiString[ByteIndex] |= Base64Digit >> 2;
                AsciiString[ByteIndex + 1] = Base64Digit << 6;
                ++ByteIndex;
                break;
            }
            case 3:
            {
                AsciiString[ByteIndex] |= Base64Digit;
                ++ByteIndex;
                break;
            }
        }
    }
    return AsciiStringLength;
}

// NOTE(brendan): OUTPUT: OutHex[] array of hex values corresponding to input
// string.  INPUT: String[], Length of String
internal void
StringToHex(u8 *OutHex, u8 *String, u32 StringLength)
{
    for (u32 StringIndex = 0;
         StringIndex < StringLength;
         ++StringIndex)
    {
        sprintf((char *)(OutHex + 2*StringIndex), "%.2x", *(String + StringIndex));
    }
}

// NOTE(brendan): swap the characters S and T (xor trick)
internal void
Swap(u8 *S, u8 *T)
{
    *S ^= *T;
    *T ^= *S;
    *S ^= *T;
}

// NOTE(brendan): reverses string String and returns pointer to start of String;
// side-effects
internal u8 *
ReverseString(u8 *String)
{
    u32 StringLength = strlen((char *)String);
    for (u32 StringIndex = 0;
         StringIndex < StringLength/2;
         ++StringIndex)
    {
        Swap(String + StringIndex, String + (StringLength - 1) - StringIndex);
    }
    return String;
}

internal u32
IntegerToBase16(u32 Value)
{
	u32 Result;

	if (Value < 10)
	{
		Result = '0' + Value;
	}
	else if ((Value >= 10) && (Value < 16))
	{
		Result = 'a' + (Value - 10);
	}
	else
	{
		INVALID_CODE_PATH;
	}

	return Result;
}

// NOTE(brendan): INPUT: hex character. OUTPUT: integer value of hex character
internal i32
Base16ToInteger(i32 Value)
{
	i32 Result;
    Value = tolower(Value);
    if ((Value >= 'a') && (Value <= 'f'))
	{
        Result = (10 + Value - 'a');
    }
	else if ((Value >= '0') && (Value <= '9'))
	{
        Result = (Value - '0');
    }
	else
	{
        Stopif(true, "Bad char passed to Base16ToInteger\n");
    }
	return Result;
}

// NOTE(brendan): INPUT: output string, hex-encoded string. OUTPUT: string
// of characters
internal void
HexStringToByteArray(u8 *Result, char *HexString, u32 Length)
{
	Stopif(Length % 2, "Length input to HexStringToByteArray must be multiple of 2\n");

    char TempString[2];
    for (u32 ResultIndex = 0;
		 ResultIndex < (Length - 1);
		 ResultIndex += 2)
	{
		sprintf(TempString, "%c", (16*Base16ToInteger(HexString[ResultIndex]) +
								   Base16ToInteger(HexString[ResultIndex + 1])));
        *Result++ = TempString[0];
    }
    *Result = 0;
}

internal u32
FileRead(u8 *OutputBuffer, char *FileName, u32 MaxLength)
{
	Stopif((OutputBuffer == 0) || (FileName == 0), "Null inputs to FileReadIgnoreSpace()\n");

    FILE *InputFile = fopen(FileName, "r");
    Stopif(!InputFile, "FileRead: No such file\n");

	u32 ResultSize = fread(OutputBuffer, 1, MaxLength, InputFile);

	fclose(InputFile);

	return ResultSize;
}

internal u32
FileReadIgnoreSpace(u8 *OutputBuffer, char *FileName, u32 MaxLength)
{
	Stopif((OutputBuffer == 0) || (FileName == 0), "Null inputs to FileReadIgnoreSpace()\n");
    FILE *InputFile = fopen(FileName, "r");
    Stopif(!InputFile, "FileReadIgnoreSpace: No such file\n");

    u32 OutBuffIndex = 0;
    for (u8 InputChar;
         ((InputChar = fgetc(InputFile)) != (u8)EOF) && (OutBuffIndex < MaxLength);
         )
    {
		if (!isspace(InputChar))
		{
			OutputBuffer[OutBuffIndex] = InputChar;
			++OutBuffIndex;
		}
    }

    fclose(InputFile);

	return OutBuffIndex;
}

internal inline void
GenRandUnchecked(u32 *RandOut, u32 LengthInWords)
{
	for (u32 RandOutIndex = 0;
		 RandOutIndex < LengthInWords;
		 ++RandOutIndex)
	{
		RandOut[RandOutIndex] = rand();
	}
}

internal inline void
GenRandBytesUnchecked(u8 *RandOut, u32 LengthInBytes)
{
	u32 WordsInRandOut = LengthInBytes/sizeof(u32);
	GenRandUnchecked((u32 *)RandOut, WordsInRandOut);

	u32 WordsInRandOutByteLength = sizeof(u32)*WordsInRandOut ;
	u32 RemainingBytes = LengthInBytes - WordsInRandOutByteLength;
	Stopif(RemainingBytes >= sizeof(u32), "Invalid remaining bytes GenRandBytesUnchecked\n");

	for (u32 RandOutByteIndex = 0;
		 RandOutByteIndex < RemainingBytes;
		 ++RandOutByteIndex)
	{
		RandOut[WordsInRandOutByteLength + RandOutByteIndex] = rand() & 0xFF;
	}
}

internal b32
CipherIsEcbEncryptedBlock(u8 *Cipher, u32 BlockCount)
{
	b32 Result = false;

	Stopif(Cipher == 0, "Null input to CipherIsEcbEncrypted\n");

	for (u32 FirstBlockIndex = 0;
		 FirstBlockIndex < (BlockCount - 1);
		 ++FirstBlockIndex)
	{
		for (u32 SecondBlockIndex = FirstBlockIndex + 1;
			 SecondBlockIndex < BlockCount;
			 ++SecondBlockIndex)
		{
			char *FirstBlock = (char *)(Cipher + FirstBlockIndex*AES_128_BLOCK_LENGTH_BYTES);
			char *SecondBlock = (char *)(Cipher + SecondBlockIndex*AES_128_BLOCK_LENGTH_BYTES);
			if (memcmp(FirstBlock, SecondBlock, AES_128_BLOCK_LENGTH_BYTES) == 0)
			{
				Result = true;
				break;
			}
		}
	}

	return Result;
}

internal b32
CipherIsEcbEncrypted(u8 *Cipher, u32 CipherLength)
{
	b32 Result;

	Stopif(Cipher == 0, "Null input to CipherIsEcbEncrypted\n");

	Result = CipherIsEcbEncryptedBlock(Cipher, CipherLength/AES_128_BLOCK_LENGTH_BYTES);

	return Result;
}

// NOTE(bwd): StrippedStringLength can be 0
// TODO(bwd): better API?
internal u8 *
StripPkcs7GetStrippedLength(u8 *PaddedString, u32 *StrippedStringLengthOut, u32 PaddedStringLength)
{
	u8 *Result = 0;
	Stopif(PaddedString == 0, "Null input to StripPkcs7Padding\n");
	Stopif((PaddedStringLength % AES_128_BLOCK_LENGTH_BYTES) != 0,
		   "Bad padded length passed to StripPkcs7GetStrippedLength\n");
	Stopif(PaddedStringLength == 0, "Invalid zero string length passed to StripPkcs7GetStrippedLength\n");

	u8 PaddingBytes = PaddedString[PaddedStringLength - 1];

	if ((PaddingBytes > 0) && (PaddingBytes <= AES_128_BLOCK_LENGTH_BYTES))
	{
		b32 ValidPadding = true;
		u8 *PaddedBlock = PaddedString + (PaddedStringLength - AES_128_BLOCK_LENGTH_BYTES);
		i32 PaddingOffsetInPaddedBlock = (AES_128_BLOCK_LENGTH_BYTES - PaddingBytes);
		for (i32 PaddedBlockIndex = (AES_128_BLOCK_LENGTH_BYTES - 1);
			 PaddedBlockIndex >= PaddingOffsetInPaddedBlock;
			 --PaddedBlockIndex)
		{
			if ((u8)PaddedBlock[PaddedBlockIndex] != PaddingBytes)
			{
				ValidPadding = false;
				break;
			}
		}
		if (ValidPadding)
		{
			*(PaddedBlock + PaddingOffsetInPaddedBlock) = 0;
			Result = PaddedString;
			if (StrippedStringLengthOut)
			{
				*StrippedStringLengthOut = (PaddedStringLength - PaddingBytes);
			}
		}
	}

	return Result;
}

internal u8 *
StripPkcs7Padding(u8 *PaddedString, u32 PaddedStringLength)
{
	u8 *Result = StripPkcs7GetStrippedLength(PaddedString, 0, PaddedStringLength);
	return Result;
}

// NOTE(brendan): INPUT: string OUTPUT: score of string, based on frequencies
// of letters (score is sum of percentages of appearance)
internal r32
ScoreString(u8 *DecodedString, u32 Length)
{
	Stopif((DecodedString == 0), "Null input to ScoreString\n");
	Stopif(Length == 0, "Invalid input (zero length) to ScoreString\n");

    u32 LetterCount[ALPHABET_SIZE] = {0};
	u32 SpacesCount = 0;
	u32 PunctCount = 0;
    r32 ResultScore = 0.0f;
    for (u32 CharIndex = 0;
		 CharIndex < Length;
		 ++CharIndex)
	{
        u8 UpperChar = toupper(DecodedString[CharIndex]);
        if (('A' <= UpperChar) && (UpperChar <= 'Z'))
		{
            ++LetterCount[UpperChar - 'A'];
        }
		else if (isspace(UpperChar))
		{
			++SpacesCount;
        }
		else if (ispunct(UpperChar))
		{
			++PunctCount;
		}
		else
		{
			ResultScore += 100.0f;
		}
		// TODO(bwd): punctuation
    }
	if (Length > SpacesCount)
	{
		for (u32 LetterIndex = 0;
			 LetterIndex < ALPHABET_SIZE;
			 ++LetterIndex)
		{
			ResultScore += (fabs(EXPECTED_LETTER_FREQUENCY[LetterIndex] -
								 (r32)LetterCount[LetterIndex]/(r32)(Length - SpacesCount)));
		}
	}

	ResultScore += fabs(EXPECTED_SPACE_FREQUENCY - (r32)SpacesCount/(r32)Length);
	ResultScore += fabs(EXPECTED_PUNCT_FREQUENCY - (r32)PunctCount/(r32)Length);

    return ResultScore;
}

// NOTE(brendan): INPUT: Ciphertext in ASCII-256, length of ciphertext.
// OUTPUT: Repeating byte forming key
// TODO(bwd): upper vs. lower case
internal u8
ByteCipherAsciiDecode(u8 *Ciphertext, u32 CipherLength)
{
    u8 Key[CipherLength];
	u8 DecodedString[CipherLength];

    r32 MinScore = INFINITY;
    u32 MinCipher = 0;
    for (u32 ByteCipher = 0;
		 ByteCipher < 256;
		 ++ByteCipher)
	{
		memset(Key, ByteCipher, CipherLength);
        XorVectorsUnchecked(DecodedString, Key, Ciphertext, CipherLength);
        for (u32 CipherIndex = 0;
             CipherIndex < CipherLength;
             ++CipherIndex)
		{
            DecodedString[CipherIndex] = Key[CipherIndex] ^ Ciphertext[CipherIndex];
        }
        r32 Score = ScoreString(DecodedString, CipherLength);
        if (Score < MinScore)
		{
            MinScore = Score;
            MinCipher = ByteCipher;
        }
    }

    return MinCipher;
}

#define MT19937_W 32
#define MT19937_N 624
#define MT19937_M 397
#define MT19937_R 31
#define MT19937_A 0x9908B0DF
#define MT19937_U 11
#define MT19937_D 0xFFFFFFFF
#define MT19937_S 7
#define MT19937_B 0x9D2C5680
#define MT19937_T 15
#define MT19937_C 0xEFC60000
#define MT19937_L 18
#define MT19937_F 1812433253

#define MT19937_LOWER_MASK ((u32)(1 << MT19937_R) - 1)
#define MT19937_UPPER_MASK (~MT19937_LOWER_MASK)

typedef struct
{
	u32 State[MT19937_N];
	u32 Index;
} mersenne_twister;

internal inline void
MtInitUnchecked(mersenne_twister *Mt)
{
	Mt->Index = MT19937_N + 1;
}

internal void
MtSeed(mersenne_twister *Mt, u32 Seed)
{
	Stopif(Mt == 0, "Null input to MtSeed\n");

	Mt->Index = MT19937_N;
	Mt->State[0] = Seed;
	for (u32 MtStateIndex = 1;
		 MtStateIndex < MT19937_N;
		 ++MtStateIndex)
	{
		Mt->State[MtStateIndex] =
			(MT19937_F*(Mt->State[MtStateIndex - 1] ^ (Mt->State[MtStateIndex - 1] >> (MT19937_W - 2))) +
			 MtStateIndex);
	}
}

internal u32
MtExtractNumber(mersenne_twister *Mt)
{
	u32 Result;

	Stopif(Mt == 0, "Null input to MtExtractNumber\n");
	Stopif(Mt->Index > MT19937_N, "Generator was never seeded\n");

	if (Mt->Index == MT19937_N)
	{
		// Twist
		for (u32 MtStateIndex = 0;
			 MtStateIndex < MT19937_N;
			 ++MtStateIndex)
		{
			u32 X = ((Mt->State[MtStateIndex] & MT19937_UPPER_MASK) +
					 (Mt->State[(MtStateIndex + 1) % MT19937_N] & MT19937_LOWER_MASK));
			u32 XA = (X >> 1);
			if (X % 2)
			{
				XA ^= MT19937_A;
			}
			Mt->State[MtStateIndex] = Mt->State[(MtStateIndex + MT19937_M) % MT19937_N] ^ XA;
		}
		Mt->Index = 0;
	}

	Result = Mt->State[Mt->Index];
	Result = Result ^ ((Result >> MT19937_U) & MT19937_D);
	Result = Result ^ ((Result << MT19937_S) & MT19937_B);
	Result = Result ^ ((Result << MT19937_T) & MT19937_C);
	Result = Result ^ (Result >> MT19937_L);

	++Mt->Index;

	return Result;
}

internal inline u32
MtUntemperStep(u32 TemperedValue, u32 Shift, u32 Mask)
{
	u32 Result = 0;
	for (u32 MaskShiftIndex = 0;
		 (MaskShiftIndex*Shift) < BITS_IN_WORD;
		 ++MaskShiftIndex)
	{
		u32 ShiftedMask = (MaskBitcount(Shift) << (MaskShiftIndex*Shift));
		Result |= ((TemperedValue ^ ((Result << Shift) & Mask)) & ShiftedMask);
	}

	return Result;
}

internal u32
MtUntemper(u32 TemperedState)
{
	u32 Result;

	Result = TemperedState ^ (TemperedState >> MT19937_L);

	Result = MtUntemperStep(Result, MT19937_T, MT19937_C);

	Result = MtUntemperStep(Result, MT19937_S, MT19937_B);

	u32 InitialMask = MaskBitcount(MT19937_U) << (BITS_IN_WORD - MT19937_U);
	u32 Temp = 0;
	for (u32 MaskShiftIndex = 0;
		 (MaskShiftIndex*MT19937_U) < BITS_IN_WORD;
		 ++MaskShiftIndex)
	{
		u32 ShiftedMask = (InitialMask >> (MaskShiftIndex*MT19937_U));
		Temp |= ((Result ^ (Temp >> MT19937_U)) & ShiftedMask);
	}
	Result = Temp;

	return Result;
}

const char PREPEND_STRING[] = "comment1=cooking%20MCs;userdata=";
#define PREPEND_LENGTH (sizeof(PREPEND_STRING) - 1)
const char APPEND_STRING[] = "comment1=cooking%20MCs;userdata=";
#define APPEND_LENGTH (sizeof(APPEND_STRING) - 1)
const char ADMIN_TRUE_STRING[] = ";admin=true;";
#define ADMIN_TRUE_STR_LENGTH (sizeof(ADMIN_TRUE_STRING) - 1)

CASSERT(ADMIN_TRUE_STR_LENGTH < (PREPEND_LENGTH - AES_128_BLOCK_LENGTH_BYTES), crypt_helper_h);

internal u32
GenRandInputAppendPrepend(u8 *RandAppendPrependInput, u32 RandInputLength)
{
	Stopif(RandAppendPrependInput == 0, "Null input to GenRandInputAppendPrepend\n");

	u8 RandValue[RandInputLength - PREPEND_LENGTH - APPEND_LENGTH];
	memcpy(RandAppendPrependInput, PREPEND_STRING, PREPEND_LENGTH);

	u32 RandomInputLengthBytes;
	RandomInputLengthBytes = rand() % sizeof(RandValue);
	GenRandBytesUnchecked(RandValue, RandomInputLengthBytes);

	u32 ScratchInputIndex = PREPEND_LENGTH;
	for (u32 RandValueIndex = 0;
		 RandValueIndex < RandomInputLengthBytes;
		 ++RandValueIndex)
	{
		u8 NextRandByte = RandValue[RandValueIndex];
		if ((NextRandByte != ';') && (NextRandByte != '='))
		{
			RandAppendPrependInput[ScratchInputIndex] = NextRandByte;
			++ScratchInputIndex;
		}
	}
	memcpy(RandAppendPrependInput + ScratchInputIndex, APPEND_STRING, APPEND_LENGTH);
	u32 TotalInputLength = (ScratchInputIndex + APPEND_LENGTH);
	Stopif(TotalInputLength > RandInputLength, "Overflowed RandAppendPrependInput\n");

	return TotalInputLength;
}

internal void
Sha1KeyedMac(u8 *KeyedMac, u8 *Message, u32 MessageLength, u8 *Key, u32 KeyLength)
{
	Stopif((KeyedMac == 0) || (Message == 0) || (Key == 0), "Null input to Sha1KeyedMac\n");

	u8 KeyConcatMessage[SHA_1_KEYED_MAC_MAX_MSG_SIZE];
	u32 TotalHmacInputSize = (MessageLength + KeyLength);
	Stopif(TotalHmacInputSize > sizeof(KeyConcatMessage), "Message + Key lengths too long in Sha1KeyedMac\n");

	memcpy(KeyConcatMessage, Key, KeyLength);
	memcpy(KeyConcatMessage + KeyLength, Message, MessageLength);

	Sha1(KeyedMac, KeyConcatMessage, TotalHmacInputSize);
}

#define SHA_1_BLOCK_SIZE 64
#define SHA_1_HMAC_MAX_HASH_INPUT_LENGTH 512
#define HMAC_RET_CODE_VALID 200
#define HMAC_RET_CODE_INVALID 500
#define HMAC_RET_CODE_LENGTH_BYTES 4

#define PORT 8181
const char IP_ADDRESS[] = "192.168.11.42";

#define TEST_USER_CMD_LENGTH (STR_LEN(TEST_SRP_PREFIX) +    \
                              STR_LEN(USER_PREFIX) + STR_LEN(SRP_TEST_VEC_EMAIL) + 1)

typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr sockaddr;
typedef struct timespec timespec;

const char SRP_TEST_VEC_EMAIL[] = "alice";
const char SRP_TEST_VEC_PASSWORD[] = "password123";

const char HMAC_VALID_STRING[] = "200";
const char HMAC_INVALID_STRING[] = "500";

const char TEST_HMAC_PREFIX[] = "test?";
const char TEST_SRP_PREFIX[] = "srp?";
const char FILE_PREFIX[] = "file=";
const char SIG_PREFIX[] = "signature=";
const char USER_PREFIX[] = "user=";
const char TEST_USER_COMMAND[] = "srp?user=alice";

internal void
OpenSocketAndConnect(i32 *SocketFileDescriptor, sockaddr_in *ServerSocketAddr)
{
    i32 Status;

    Stopif((SocketFileDescriptor == 0) || (ServerSocketAddr == 0), "Null input to OpenSocketAndConnect!\n");

    *SocketFileDescriptor = socket(AF_INET, SOCK_STREAM, 0);
    Stopif(*SocketFileDescriptor < 0, "Error from socket() call in OpenSocketAndConnect!\n");

    Status = connect(*SocketFileDescriptor, (sockaddr *)ServerSocketAddr, sizeof(*ServerSocketAddr));
    Stopif(Status < 0, "Error from connect() call in OpenSocketAndConnect!\n");
}

internal void
HmacSha1(u8 *Hmac, u8 *Message, u32 MessageLength, u8 *Key, u32 KeyLength)
{
	Stopif((Hmac == 0) || (Message == 0) || (Key == 0), "Null input to HmacSha1\n");
	u32 TotalHashedInputSize = (SHA_1_BLOCK_SIZE + MessageLength);
	Stopif(TotalHashedInputSize > SHA_1_HMAC_MAX_HASH_INPUT_LENGTH, "Buffer overflow in HmacSha1\n");

	u8 KeyScratch[SHA_1_BLOCK_SIZE];
	u8 *K_0;
	if (KeyLength == SHA_1_BLOCK_SIZE)
	{
		K_0 = Key;
	}
	else if (KeyLength > SHA_1_BLOCK_SIZE)
	{
		Sha1(KeyScratch, Key, KeyLength);
		memset(KeyScratch + SHA_1_HASH_LENGTH_BYTES, 0, sizeof(KeyScratch) - SHA_1_HASH_LENGTH_BYTES);
		K_0 = KeyScratch;
	}
	else
	{
		memcpy(KeyScratch, Key, KeyLength);
		memset(KeyScratch + KeyLength, 0, sizeof(KeyScratch) - KeyLength);
		K_0 = KeyScratch;
	}

	u8 HmacScratch[SHA_1_HMAC_MAX_HASH_INPUT_LENGTH];
	for (u32 HmacScratchByteIndex = 0;
		 HmacScratchByteIndex < SHA_1_BLOCK_SIZE;
		 ++HmacScratchByteIndex)
	{
		HmacScratch[HmacScratchByteIndex] = K_0[HmacScratchByteIndex] ^ 0x36;
	}
	memcpy(HmacScratch + SHA_1_BLOCK_SIZE, Message, MessageLength);
	Sha1(HmacScratch + SHA_1_BLOCK_SIZE, HmacScratch, TotalHashedInputSize);

	for (u32 HmacScratchByteIndex = 0;
		 HmacScratchByteIndex < SHA_1_BLOCK_SIZE;
		 ++HmacScratchByteIndex)
	{
		HmacScratch[HmacScratchByteIndex] = K_0[HmacScratchByteIndex] ^ 0x5C;
	}

	Sha1(Hmac, HmacScratch, SHA_1_BLOCK_SIZE + SHA_1_HASH_LENGTH_BYTES);
}

#define BITS_IN_BIGNUM_WORD     64
#define BYTES_IN_BIGNUM_WORD    (BITS_IN_BIGNUM_WORD/BITS_IN_BYTE)
#define MAX_BIGNUM_SIZE_BITS    4096
#define MAX_BIGNUM_SIZE_BYTES   (MAX_BIGNUM_SIZE_BITS/BITS_IN_BYTE)
#define MAX_BIGNUM_SIZE_WORDS   (MAX_BIGNUM_SIZE_BYTES/sizeof(u64))
#define MAX_BIT_IN_BIGNUM_WORD  (BITS_IN_BIGNUM_WORD - 1)

#define GET_HIGHEST_BIGNUM_BIT(BigNum) ((BigNum) >> MAX_BIT_IN_BIGNUM_WORD)

typedef struct
{
    u64 Num[MAX_BIGNUM_SIZE_WORDS];
    u32 SizeWords;
    b32 Negative;
} bignum;

// Little-endian
const bignum NIST_RFC_3526_PRIME_1536 =
{
    .Num =
    {
        0xFFFFFFFFFFFFFFFF, 0xF1746C08CA237327, 0x670C354E4ABC9804, 0x9ED529077096966D, 0x1C62F356208552BB,
        0x83655D23DCA3AD96, 0x69163FA8FD24CF5F, 0x98DA48361C55D39A, 0xC2007CB8A163BF05, 0x49286651ECE45B3D,
        0xAE9F24117C4B1FE6, 0xEE386BFB5A899FA5, 0xBFF5CB6F406B7ED, 0xF44C42E9A637ED6B, 0xE485B576625E7EC6,
        0x4FE1356D6D51C245, 0x302B0A6DF25F1437, 0xEF9519B3CD3A431B, 0x514A08798E3404DD, 0x20BBEA63B139B22,
        0x29024E088A67CC74, 0xC4C6628B80DC1CD1, 0xC90FDAA22168C234, 0xFFFFFFFFFFFFFFFF,
    },
    .SizeWords = 24
};

#define NIST_RFC_3526_GEN 2

const bignum NIST_RFC_3526_GEN_BIGNUM =
{
    .Num =
    {
        NIST_RFC_3526_GEN
    },
    .SizeWords = 1
};

#define NIST_RFC_5054_GEN 2

const bignum NIST_RFC_5054_GEN_BIGNUM =
{
    .Num =
    {
        NIST_RFC_5054_GEN
    },
    .SizeWords = 1
};

const bignum RFC_5054_NIST_PRIME_1024 =
{
    .Num =
    {
        0x9FC61D2FC0EB06E3, 0xFD5138FE8376435B, 0x2FD4CBF4976EAA9A, 0x68EDBC3C05726CC0, 0xC529F566660E57EC,
        0x82559B297BCF1885, 0xCE8EF4AD69B15D49, 0x5DC7D7B46154D6B6, 0x8E495C1D6089DAD1, 0xE0D5D8E250B98BE4,
        0x383B4813D692C6E0, 0xD674DF7496EA81D3, 0x9EA2314C9C256576, 0x6072618775FF3C0B, 0x9C33F80AFA8FC5E8,
        0xEEAF0AB9ADB38DD6, 
    },
    .SizeWords = 16
};

const bignum RFC_5054_TEST_SALT =
{
    .Num =
    {
        0xB5A727673A2441EE, 0xBEB25379D1A8581E, 
    },
    .SizeWords = 2
};

const bignum RFC_5054_TEST_K =
{
    .Num =
    {
        0x665C3E818913186F, 0x5AEF2CDD07ABAF0F, 0x7556AA04, 
    },
    .SizeWords = 3
};

const bignum RFC_5054_TEST_X =
{
    .Num =
    {
        0x93DB6CF84D16C124, 0xABE9127CC58CCF49, 0x94B7555A, 
    },
    .SizeWords = 3
};

const bignum RFC_5054_TEST_V =
{
    .Num =
    {
        0xDB2BE315E2099AFB, 0xE955A5E29E7AB245, 0x33B564E26480D78, 0xE058AD51CC72BFC9, 0x1AFF87B2B9DA6E04,
        0x52E08AB5EA53D15C, 0xBBF4CEBFBB1681, 0x48CF1970B4FB6F84, 0xC671085A1447B52A, 0xF105B4787E5186F5,
        0xE379BA4729FDC59, 0x822223CA1A605B53, 0x9886D8129BADA1F1, 0xB0DDE1569E8FA00A, 0x4E337D05B4B375BE,
        0x7E273DE8696FFC4F, 
    },
    .SizeWords = 16
};

const bignum RFC_5054_TEST_LITTLE_A =
{
    .Num =
    {
        0xAFD529DDDA2D4393, 0xC81EDC04E2762A56, 0x1989806F0407210B, 0x60975527035CF2AD, 
    },
    .SizeWords = 4
};

const bignum RFC_5054_TEST_LITTLE_B =
{
    .Num =
    {
        0x9E61F5D105284D20, 0x1DDA08E974A004F4, 0x471E81F00F6928E0, 0xE487CB59D31AC550, 
    },
    .SizeWords = 4
};

const bignum RFC_5054_TEST_BIG_A =
{
    .Num =
    {
        0x72FAC47B0769447B, 0xB349EF5D76988A36, 0x58F0EDFDFE15EFEA, 0xEEF54073CA11CF58, 0x6530E69F66615261,
        0xE1327F44BE087EF0, 0x71E1E8B9AF6D9C03, 0x42BA92AEACED8251, 0x8E39356179EAE45E, 0xBFCF99F921530EC,
        0x2D1A5358A2CF1B6E, 0x3211C04692272D8B, 0x72557EC44352E890, 0xD0E560F0C64115BB, 0x47B0704C436F523D,
        0x61D5E490F6F1B795, 
    },
    .SizeWords = 16
};

const bignum RFC_5054_TEST_BIG_B =
{
    .Num =
    {
        0xA8E3FB004B117B58, 0xEB4012B7D7665238, 0x910440B1B27AAEAE, 0x30B331EB76840, 0x9C6059F388838E7A,
        0x7BD4FBAA37089E6F, 0xD7D82C7F8DEB75CE, 0xD0C6DDB58B318885, 0x6C6DA04453728610, 0xB681CBF87837EC99,
        0x5A981652236F99D9, 0xDC46A0670DD125B9, 0x5393011BAF38964, 0x4916A1E77AF46AE1, 0xB6D041FA01BB152D,
        0xBD0C61512C692C0C, 
    },
    .SizeWords = 16
};

const bignum RFC_5054_TEST_U =
{
    .Num =
    {
        0x70A7AE5F462EF019, 0x3487DA98554ED47D, 0xCE38B959, 
    },
    .SizeWords = 3
};

const bignum RFC_5054_TEST_PREMASTER_SECRET =
{
    .Num =
    {
        0x8A469FFECA686E5A, 0xC346D7E474B29EDE, 0xBE5BEC4EC0A3212D, 0x3CD67FC88A2F39A4, 0x210DCC1F10EB3394,
        0x2AFAFA8F3499B200, 0xBDCAF8A709585EB, 0xA172B4A2A5903A, 0x41BB59B6D5979B5C, 0x876E2D013800D6C,
        0x9AE12B0A6F67809F, 0x59B48220F7C4693C, 0xF271A10D233861E3, 0x90A3381F63B387AA, 0xAE450C0287745E79,
        0xB0DC82BABCF30674,
    },
    .SizeWords = 16
};

internal inline u32
BigNumSizeBytesUnchecked(bignum *BigNum)
{
    u32 Result = BigNum->SizeWords*sizeof(BigNum->Num[0]);

    return Result;
}

internal inline void
BigNumCopyUnchecked(bignum *Dest, bignum *Source)
{
    Dest->SizeWords = Source->SizeWords;
    memcpy(Dest->Num, Source->Num, BigNumSizeBytesUnchecked(Source));
}

internal inline u64
CheckForCarry(u64 Sum, u64 AdditionOperand)
{
    u64 Carry;

    if (Sum < AdditionOperand)
    {
        Carry = 1;
    }
    else
    {
        Carry = 0;
    }

    return Carry;
}

internal inline void
AdjustSizeWordsDownUnchecked(bignum *BigNum)
{
	while ((BigNum->SizeWords > 0) &&
		   (BigNum->Num[BigNum->SizeWords - 1] == 0))
	{
		--BigNum->SizeWords;
	}
}

internal b32
IsAGreaterThanB(bignum *A, bignum *B)
{
	b32 Result = false;

	Stopif((A == 0) || (B == 0), "Null input to IsAGreaterThanB\n");

	if (A->SizeWords > B->SizeWords)
	{
		Result = true;
	}
	else if (A->SizeWords < B->SizeWords)
	{
		Result = false;
	}
	else
	{
		for (i32 AIndex = (A->SizeWords - 1);
			 AIndex >= 0;
			 --AIndex)
		{
			if (A->Num[AIndex] > B->Num[AIndex])
			{
				Result = true;
				break;
			}
			else if (A->Num[AIndex] < B->Num[AIndex])
			{
				Result = false;
				break;
			}
		}
	}

	return Result;
}

internal b32
IsAGreaterThanOrEqualToB(bignum *A, bignum *B)
{
    b32 Result = !IsAGreaterThanB(B, A);

    return Result;
}

internal u32
MultiPrecisionAdd(u64 *SumAB, u32 *SumLengthWords,
                  u64 *A, u32 ALengthWords,
                  u64 *B, u32 BLengthWords)
{
    Stopif((SumAB == 0) || (SumLengthWords == 0) || (A == 0) || (B == 0), "Null input to MultiPrecisionAdd!\n");

    u32 MaxSize = Maximum(ALengthWords, BLengthWords);

    u32 Carry = 0;

    u32 SumABIndex = 0;
    u64 AdditionOperand;
    do
    {
        if (SumABIndex >= ALengthWords)
        {
            AdditionOperand = B[SumABIndex];

            SumAB[SumABIndex] = B[SumABIndex] + Carry;

            Carry = CheckForCarry(SumAB[SumABIndex], AdditionOperand);
        }
        else if (SumABIndex >= BLengthWords)
        {
            AdditionOperand = A[SumABIndex];

            SumAB[SumABIndex] = A[SumABIndex] + Carry;

            Carry = CheckForCarry(SumAB[SumABIndex], AdditionOperand);
        }
        else
        {
            AdditionOperand = A[SumABIndex];

            u64 RightOperand = B[SumABIndex] + Carry;

            Carry = CheckForCarry(RightOperand, B[SumABIndex]);

            SumAB[SumABIndex] = A[SumABIndex] + RightOperand;

            if (Carry == 0)
            {
                Carry = CheckForCarry(SumAB[SumABIndex], AdditionOperand);
            }
        }

        ++SumABIndex;
    } while (SumABIndex < MaxSize);

    if (Carry && (MaxSize < (*SumLengthWords)))
    {
        Carry = 0;
        SumAB[MaxSize] = 1;
        *SumLengthWords = MaxSize + 1;
    }
    else
    {
        *SumLengthWords = MaxSize;
    }

    return Carry;
}

// IN: integers A, B in [0, 2^(W*t))
// OUT: (eps, C) where C = A + B mod 2^(W*t), and eps is the carry bit
internal u32 
BigNumAdd(bignum *SumAB, bignum *A, bignum *B)
{
    Stopif((SumAB == 0) || (A == 0) || (B == 0), "Null input to BigNumAdd!\n");

    bignum LocalSumAB;
    LocalSumAB.SizeWords = MAX_BIGNUM_SIZE_WORDS;

    u32 Carry = MultiPrecisionAdd(LocalSumAB.Num, &LocalSumAB.SizeWords,
                                  A->Num, A->SizeWords,
                                  B->Num, B->SizeWords);

    AdjustSizeWordsDownUnchecked(&LocalSumAB);

    BigNumCopyUnchecked(SumAB, &LocalSumAB);

    return Carry;
}

internal inline u64
CheckForBorrow(u64 Difference, u64 LeftOperand)
{
    u64 Borrow;

    if (Difference > LeftOperand)
    {
        Borrow = 1;
    }
    else
    {
        Borrow = 0;
    }

    return Borrow;
}

internal u32
BigNumUnsignedSubtract(bignum *AMinusB, bignum *A, bignum *B)
{
    u32 Borrow = 0;

    u64 LeftOperand = A->Num[0];
    AMinusB->Num[0] = LeftOperand - B->Num[0];
    if (AMinusB->Num[0] > LeftOperand)
    {
        Borrow = 1;
    }

    u32 AMinusBIndex = 1;
    do
    {
        // Since A is greater than B, we must have A->SizeWords >= B->SizeWords, so no need to check
        // for AMinusBIndex >= A->SizeWords case (i.e. MaxSize == A->SizeWords)
        LeftOperand = A->Num[AMinusBIndex];
        if (AMinusBIndex >= B->SizeWords)
        {
            AMinusB->Num[AMinusBIndex] = LeftOperand - Borrow;

            Borrow = CheckForBorrow(AMinusB->Num[AMinusBIndex], LeftOperand);
        }
        else
        {
            u64 RightOperand = B->Num[AMinusBIndex] + Borrow;

            Borrow = CheckForCarry(RightOperand, B->Num[AMinusBIndex]);

            AMinusB->Num[AMinusBIndex] = LeftOperand - RightOperand;

            if (Borrow == 0)
            {
                Borrow = CheckForBorrow(AMinusB->Num[AMinusBIndex], LeftOperand);
            }
        }

        ++AMinusBIndex;
    } while (AMinusBIndex < A->SizeWords);

    Stopif(Borrow, "Negative numbers currently not supported.\n");

    AMinusB->SizeWords = A->SizeWords;
    AdjustSizeWordsDownUnchecked(AMinusB);

    return Borrow;
}

// TODO(bwd): Test signed-ness + add signed addition, multiplication, etc? Or asserts
internal u32 
BigNumSubtract(bignum *AMinusB, bignum *A, bignum *B)
{
    Stopif((AMinusB == 0) || (A == 0) || (B == 0), "Null input to BigNumSubtract!\n");

    /*-
     *  a -  b      a-b
     *  a - -b      a+b
     * -a -  b      -(a+b)
     * -a - -b      b-a
     */
    if (A->Negative)
    {
        if (B->Negative)
        {
            bignum *Temp = A;
            A = B;
            B = Temp;
        }
        else
        {
            // Add, neg
        }
    }
    else if (B->Negative)
    {
        // Add, pos
    }

    u32 Borrow;
    if (IsAGreaterThanB(A, B))
    {
        Borrow = BigNumUnsignedSubtract(AMinusB, A, B);
        AMinusB->Negative = false;
    }
    else
    {
        Borrow = BigNumUnsignedSubtract(AMinusB, B, A);
        AMinusB->Negative = true;
    }

    return Borrow;
}

internal void
BigNumSubtractModP(bignum *AMinusBModP, bignum *AModP, bignum *BModP, bignum *P)
{
    Stopif((AMinusBModP == 0) || (AModP == 0) || (BModP == 0) || (P == 0),
           "Null input to BigNumSubtractModP!");

    Stopif(IsAGreaterThanOrEqualToB(AModP, P) || IsAGreaterThanOrEqualToB(BModP, P),
           "Inputs to BigNumSubtractModP must be in [0, P)!");

    if (IsAGreaterThanB(BModP, AModP))
    {
        bignum LocalAPlusP;
        BigNumAdd(&LocalAPlusP, AModP, P);

        BigNumSubtract(AMinusBModP, &LocalAPlusP, BModP);
    }
    else
    {
        BigNumSubtract(AMinusBModP, AModP, BModP);
    }

}

internal void
GenRandBigNumModNUnchecked(bignum *A, bignum *N)
{
    GenRandUnchecked((u32 *)A->Num, 2*N->SizeWords);

    u32 BitCountNHighestDWord = BIT_COUNT_DWORD(N->Num[N->SizeWords - 1]);

    Stopif((BitCountNHighestDWord == 0) || (BitCountNHighestDWord > BITS_IN_DWORD),
           "Invalid N->SizeWords in GenRandBigNumModNUnchecked!\n");

    if (BitCountNHighestDWord < BITS_IN_DWORD)
    {
        A->Num[N->SizeWords - 1] &= MaskBitcount(BitCountNHighestDWord);
    }

    A->SizeWords = N->SizeWords;
    AdjustSizeWordsDownUnchecked(A);

    if (!IsAGreaterThanB(N, A))
    {
        BigNumSubtract(A, A, N);
    }

    Stopif(!IsAGreaterThanB(N, A), "Invalid RandBigNum output in GenRandBigNumModNUnchecked!\n");
}

internal void 
BigNumAddModN(bignum *SumABModN, bignum *A, bignum *B, bignum *N)
{
	Stopif((SumABModN == 0) || (A == 0) || (B == 0) || (N == 0), "Null input to BigNumAdd!\n");

    u32 Carry = BigNumAdd(SumABModN, A, B);

    if (Carry)
    {
        BigNumSubtract(SumABModN, SumABModN, N);
    }
    else if (!IsAGreaterThanB(N, SumABModN))
    {
        BigNumSubtract(SumABModN, SumABModN, N);
    }
}

internal void
ByteSwap(u8 *Buffer, u32 Length)
{
	for (u32 BufferIndex = 0;
		 BufferIndex < (Length/2);
		 ++BufferIndex)
	{
		u8 Temp = Buffer[Length - 1 - BufferIndex];
		Buffer[Length - 1 - BufferIndex] = Buffer[BufferIndex];
		Buffer[BufferIndex] = Temp;
	}
}

#define INVALID_LENGTH_WORDS(A, ALengthWords) (((ALengthWords) > 0) && ((A)[(ALengthWords) - 1] == 0))

internal u32
MultiplyOperandScanningUnchecked(u64 *ProductAB, u32 ProductABMaxLengthWords,
                                 u64 *A, u32 ALengthWords,
                                 u64 *B, u32 BLengthWords)
{
    Stopif(INVALID_LENGTH_WORDS(A, ALengthWords) || INVALID_LENGTH_WORDS(B, BLengthWords),
           "Invalid LengthWords parameter in MultiplyOperandScanningUnchecked!\n");

    memset(ProductAB, 0, sizeof(u64)*ProductABMaxLengthWords);

    for (u32 AIndex = 0;
         AIndex < ALengthWords;
         ++AIndex)
    {
        u128 UV = 0;

        for (u32 BIndex = 0;
             (BIndex < BLengthWords) && ((AIndex + BIndex) < ProductABMaxLengthWords);
             ++BIndex)
        {
            UV = (ProductAB[AIndex + BIndex] + ((u128)A[AIndex])*((u128)B[BIndex]) + (UV >> BITS_IN_DWORD));

            ProductAB[AIndex + BIndex] = UV & MASK_64BIT;
        }

        if ((BLengthWords + AIndex) < ProductABMaxLengthWords)
        {
            ProductAB[BLengthWords + AIndex] = (UV >> BITS_IN_DWORD);
        }
    }

    // Extra word is because
    // (a_31*2^31 + ... + a_0*2^0)*(b_31*2^31 + ... + b_0*2^0) == c_62*2^62 + ... + c_0*2^0
    u32 ResultSizeWords = (ALengthWords + BLengthWords + 1);
    if (ResultSizeWords > ProductABMaxLengthWords)
    {
        ResultSizeWords = ProductABMaxLengthWords;
    }

	while (INVALID_LENGTH_WORDS(ProductAB, ResultSizeWords))
	{
		--ResultSizeWords;
	}

    return ResultSizeWords;
}

internal void
BigNumMultiplyOperandScanning(bignum *ProductAB, bignum *A, bignum *B)
{
    Stopif((ProductAB == 0) || (A == 0) || (B == 0), "Null input to BigNumMultiplyModNOperandScanning!\n");

    bignum TempProductAB;

    TempProductAB.SizeWords = MultiplyOperandScanningUnchecked(TempProductAB.Num, MAX_BIGNUM_SIZE_WORDS,
                                                               A->Num, A->SizeWords,
                                                               B->Num, B->SizeWords);

    memcpy(ProductAB, &TempProductAB, sizeof(TempProductAB));
}

internal inline b32
IsInverseOfNMod2PowerKUnchecked(bignum *BigNum, bignum *BigNumInverse, u32 PowerOf2)
{
    Stopif(PowerOf2 > MAX_BIGNUM_SIZE_BITS, "Invalid PowerOf2 in IsInverseOfNMod2PowerKUnchecked!\n");

    // TODO(bwd): copy BigNum mod 2^k and multiply with BigNum' mod 2^k to get BigNum*BigNum' mod 2^k
    bignum ScratchProduct;
    BigNumMultiplyOperandScanning(&ScratchProduct, BigNumInverse, BigNum);

    u32 NextPowerOf2DWordIndex;
    if (PowerOf2 < MAX_BIGNUM_SIZE_BITS)
    {
        NextPowerOf2DWordIndex = PowerOf2 / BITS_IN_DWORD;
        ScratchProduct.Num[NextPowerOf2DWordIndex] &= BITMASK_MOD_DWORD(PowerOf2);
    }
    else
    {
        NextPowerOf2DWordIndex = MAX_BIGNUM_SIZE_WORDS - 1;
    }

    b32 NInverted = true;
    for (u32 ProductIndex = NextPowerOf2DWordIndex;
         ProductIndex > 0;
         --ProductIndex)
    {
        if (ScratchProduct.Num[ProductIndex] != 0)
        {
            NInverted = false;
            break;
        }
    }

    if (NInverted && (ScratchProduct.Num[0] != 1))
    {
        NInverted = false;
    }

    return NInverted;
}

internal void
FindNInverseModR(bignum *NInverseModR, bignum *N, u32 RPowerOf2)
{
    Stopif((N->SizeWords > MAX_BIGNUM_SIZE_WORDS) || (N->SizeWords == 0) || (!(N->Num[0] & 0x1)),
           "gcd(N, R) must be 1 in FindNInverseModR!\n");

    Stopif(RPowerOf2 > MAX_BIGNUM_SIZE_BITS, "RPowerOf2 too large in FindNInverseModR!\n");

    Stopif(RPowerOf2 % BITS_IN_DWORD, "RPowerOf2 not multiple of 64 in FindNInverseModR!\n");

    // Hensel's Lemma to calculate 1/N mod R -- used to avoid explicit trial division

    NInverseModR->SizeWords = 1;
    NInverseModR->Num[0] = 1;

    u32 NextPowerOf2 = 1;
    while (NextPowerOf2 < RPowerOf2)
    {
        // To keep the invariant (NInverseModR * N) == 1 mod NextPowerOf2 ...
        ++NextPowerOf2;

        u32 NextPowerOf2DWordIndex = NextPowerOf2 / BITS_IN_DWORD;
        u32 NextPowerOf2Mod64 = (NextPowerOf2 % BITS_IN_DWORD);
        b32 NoOverflow = (NextPowerOf2DWordIndex < MAX_BIGNUM_SIZE_WORDS);
        if ((NextPowerOf2Mod64 == 0) && NoOverflow)
        {
            NInverseModR->Num[NextPowerOf2DWordIndex] = 0;
        }

        if (!IsInverseOfNMod2PowerKUnchecked(N, NInverseModR, NextPowerOf2))
        {
            if (NextPowerOf2Mod64 > 0)
            {
                NInverseModR->Num[NextPowerOf2DWordIndex] |= ((u64)1 << (NextPowerOf2Mod64 - 1));
            }
            else
            {
                NInverseModR->Num[NextPowerOf2DWordIndex - 1] |= ((u64)1 << (BITS_IN_DWORD - 1));
            }
        }

        if (NoOverflow)
        {
            NInverseModR->SizeWords = NextPowerOf2DWordIndex + 1;
        }
        else
        {
            NInverseModR->SizeWords = NextPowerOf2DWordIndex;
        }

        AdjustSizeWordsDownUnchecked(NInverseModR);

        Stopif(!IsInverseOfNMod2PowerKUnchecked(N, NInverseModR, NextPowerOf2),
               "1/N mod R not found in FindNInverseModR!\nNextPowerOf2: %d\n", NextPowerOf2);
    }
}

internal void
MultiplyByRModP(bignum *Output, bignum *InputX, bignum *ModulusP, u32 RPowerOf2)
{
    Stopif((Output == 0) || (InputX == 0) || (ModulusP == 0), "Null InputX to MultiplyByRModP!\n");

    BigNumCopyUnchecked(Output, InputX);

    if (Output->SizeWords > 0)
    {
        for (u32 RPowerIndex = 0;
             RPowerIndex < RPowerOf2;
             ++RPowerIndex)
        {
            u32 PrevMontInputWordHighBit = GET_HIGHEST_BIGNUM_BIT(Output->Num[0]);

            Output->Num[0] <<= 1;

            for (u32 InputIndex = 1;
                 InputIndex < Output->SizeWords;
                 ++InputIndex)
            {
                u64 TempMontInputWord = Output->Num[InputIndex];

                Output->Num[InputIndex] = (Output->Num[InputIndex] << 1) | PrevMontInputWordHighBit;

                PrevMontInputWordHighBit = GET_HIGHEST_BIGNUM_BIT(TempMontInputWord);
            }

            if (Output->SizeWords < MAX_BIGNUM_SIZE_WORDS)
            {
                Output->Num[Output->SizeWords] = PrevMontInputWordHighBit;

                if (PrevMontInputWordHighBit)
                {
                    ++Output->SizeWords;
                }
            }

            if (IsAGreaterThanB(Output, ModulusP))
            {
                BigNumSubtract(Output, Output, ModulusP);
            }

            Stopif(IsAGreaterThanOrEqualToB(Output, ModulusP),
                   "Output < ModulusP pre-condition broken for RPowerIndex %d in MultiplyByRModP!\n",
                   RPowerIndex);
        }
    }
}

internal void
GetZRInverseModP(bignum *Output,
                 u64 *InputZ,
                 u32 ZLengthDWords,
                 bignum *ModulusP,
                 bignum *MinusPInverseModR,
                 u32 RPowerOf2)
{
    Stopif((Output == 0) ||
           (InputZ == 0) ||
           (ModulusP == 0) ||
           (MinusPInverseModR == 0),
           "Null input to GetZRInverseModP!\n");

    // c := (z + (z*p' mod R)*p)/R

    // Output := (z*p' mod R)
    u32 MaxDWordsModR;
    u32 RPowerOf2ModDWord = (RPowerOf2 % BITS_IN_DWORD);
    if (RPowerOf2ModDWord)
    {
        MaxDWordsModR = RPowerOf2/BITS_IN_DWORD + 1;
    }
    else
    {
        MaxDWordsModR = RPowerOf2/BITS_IN_DWORD;
    }

    bignum LocalOutput;
    LocalOutput.SizeWords = MultiplyOperandScanningUnchecked(LocalOutput.Num,
                                                             MaxDWordsModR,
                                                             InputZ,
                                                             ZLengthDWords,
                                                             MinusPInverseModR->Num,
                                                             MinusPInverseModR->SizeWords);

    u64 RBitmaskMod2Pow64 = BITMASK_MOD_DWORD(RPowerOf2);
    if (RBitmaskMod2Pow64 && (LocalOutput.SizeWords > 0))
    {
        LocalOutput.Num[LocalOutput.SizeWords - 1] &= RBitmaskMod2Pow64;
    }

    // PTimesZPModR := (z*p' mod R)*p 
    u64 PTimesZPModR[2*MAX_BIGNUM_SIZE_WORDS];
    u32 PZModRLengthDWords = MultiplyOperandScanningUnchecked(PTimesZPModR,
                                                              ARRAY_LENGTH(PTimesZPModR),
                                                              LocalOutput.Num,
                                                              LocalOutput.SizeWords,
                                                              ModulusP->Num,
                                                              ModulusP->SizeWords);

    // DoubleBignumScratch := (z + (z*p' mod R)*p)
    u64 DoubleBignumScratch[2*MAX_BIGNUM_SIZE_WORDS];
    u32 NumeratorLength = ARRAY_LENGTH(DoubleBignumScratch);
    MultiPrecisionAdd(DoubleBignumScratch,
                      &NumeratorLength,
                      InputZ,
                      ZLengthDWords,
                      PTimesZPModR,
                      PZModRLengthDWords);

    // Output := (z + (z*p' mod R)*p)/R
    u32 TruncatedStartIndex;
    if (RPowerOf2ModDWord)
    {
        TruncatedStartIndex = MaxDWordsModR - 1;
    }
    else
    {
        TruncatedStartIndex = MaxDWordsModR;
    }

    LocalOutput.SizeWords = NumeratorLength - TruncatedStartIndex;
    memcpy(LocalOutput.Num, DoubleBignumScratch + TruncatedStartIndex, sizeof(u64)*LocalOutput.SizeWords);

    Stopif(LocalOutput.Num[LocalOutput.SizeWords - 1] == 0, "Invalid SizeWords in MontInner!\n");

    if (RPowerOf2ModDWord)
    {
        for (u32 OutputIndex = 0;
             OutputIndex < LocalOutput.SizeWords;
             ++OutputIndex)
        {
            LocalOutput.Num[OutputIndex] >>= RPowerOf2ModDWord;
        }
    }

    AdjustSizeWordsDownUnchecked(&LocalOutput);

    // if c >= p then c := c - p
    if (IsAGreaterThanOrEqualToB(&LocalOutput, ModulusP))
    {
        BigNumSubtract(&LocalOutput, &LocalOutput, ModulusP);
    }

    memcpy(Output, &LocalOutput, sizeof(LocalOutput));
}

internal void
FindMinusNInverseModR(bignum *MinusPInverseModR, bignum *ModulusP, u32 RPowerOf2)
{
    Stopif(RPowerOf2 % BITS_IN_DWORD, "Non-DWord aligned R not supported in FindMinusNInverseModR!\n");

    FindNInverseModR(MinusPInverseModR, ModulusP, RPowerOf2);

    u32 Borrow = 0;

    // TODO(bwd): SizeWords -> R size in DWords
    for (u32 MinusNInvIndex = 0;
         MinusNInvIndex < MinusPInverseModR->SizeWords;
         ++MinusNInvIndex)
    {
        MinusPInverseModR->Num[MinusNInvIndex] = -MinusPInverseModR->Num[MinusNInvIndex] - Borrow;

        Borrow = CheckForBorrow(MinusPInverseModR->Num[MinusNInvIndex], 0);
    }
}

internal void
BigNumMultiplyModP(bignum *ProductABModP, bignum *A, bignum *B, bignum *P)
{
    Stopif((ProductABModP == 0) || (A == 0) || (B == 0)|| (P == 0), "Null InputX to BigNumMultiplyModP!\n");

    if ((A->SizeWords == 0) || (B->SizeWords == 0))
    {
        // If A or B are zero, the result will be zero mod P, so we check for this case
        ProductABModP->SizeWords = 0;
    }
    else
    {
        bignum LocalProductABModP;
        BigNumMultiplyOperandScanning(&LocalProductABModP, A, B);

        // Reduce k*g^x mod P to satisfy BigNumSubtract function
        bignum MinusPInverseModR;
        FindMinusNInverseModR(&MinusPInverseModR, P, MAX_BIGNUM_SIZE_BITS);

        GetZRInverseModP(&LocalProductABModP,
                         LocalProductABModP.Num,
                         LocalProductABModP.SizeWords,
                         P,
                         &MinusPInverseModR,
                         MAX_BIGNUM_SIZE_BITS);

        MultiplyByRModP(ProductABModP, &LocalProductABModP, P, MAX_BIGNUM_SIZE_BITS);
    }
}

internal void
MontInner(bignum *Output, bignum *XTimesRModP, bignum *YTimesRModP, bignum *ModulusP,
          bignum *MinusPInverseModR, u32 RPowerOf2)
{
    Stopif((Output == 0) ||
           (XTimesRModP == 0) ||
           (YTimesRModP == 0) ||
           (ModulusP == 0) ||
           (MinusPInverseModR == 0),
           "Null input to MontInner!\n");

    Stopif((RPowerOf2 & (RPowerOf2 - 1)) != 0, "R not power of 2 in MontInner!\n");

    // DoubleBignumScratch := z ( == (x*R mod P)*(y*R mod P))
    u64 DoubleBignumScratch[2*MAX_BIGNUM_SIZE_WORDS];

    u32 ZLengthDWords = MultiplyOperandScanningUnchecked(DoubleBignumScratch, ARRAY_LENGTH(DoubleBignumScratch),
                                                         XTimesRModP->Num, XTimesRModP->SizeWords,
                                                         YTimesRModP->Num, YTimesRModP->SizeWords);

    GetZRInverseModP(Output, DoubleBignumScratch, ZLengthDWords, ModulusP, MinusPInverseModR, RPowerOf2);
}

internal void
MontModExp(bignum *OutputA, bignum *InputX, bignum *ExponentE, bignum *ModulusP, u32 RPowerOf2)
{
    Stopif((OutputA == 0) || (InputX == 0) || (ExponentE == 0) || (ModulusP == 0),
           "Null InputX to MontModExp!\n");

    Stopif(ModulusP->SizeWords == 0, "Invalid ModulusP in MontModExp!\n");

    if (IsAGreaterThanOrEqualToB(InputX, ModulusP))
    {
        BigNumSubtract(InputX, InputX, ModulusP);
    }

    Stopif(IsAGreaterThanOrEqualToB(InputX, ModulusP), "InputX >= 2*P in MontModExp!\n");

    // TODO(bwd): InputX belongs to [0, R*ModulusP - 1] pre-condition
    // TODO(bwd): return 0 for ModulusP == 1

    if ((InputX->Num[0] == 1) && (InputX->SizeWords == 1))
    {
        OutputA->Num[0] = 1;
        OutputA->SizeWords = 1;
    }
    else
    {
        // Calculate result locally in case OutputA and one of the inputs are the same
        bignum LocalResult;

        if (InputX->SizeWords > 0)
        {
            bignum MinusPInverseModR;
            FindMinusNInverseModR(&MinusPInverseModR, ModulusP, RPowerOf2);

            // x~ := x*R mod p
            bignum InputXTimesRModP;
            MultiplyByRModP(&InputXTimesRModP, InputX, ModulusP, RPowerOf2);

            // A := R mod p
            LocalResult.Num[0] = 1;
            LocalResult.SizeWords = 1;
            MultiplyByRModP(&LocalResult, &LocalResult, ModulusP, RPowerOf2);

            u32 BitCountExponentE = ((BITS_IN_DWORD*(ExponentE->SizeWords - 1)) +
                                     BIT_COUNT_DWORD(ExponentE->Num[ExponentE->SizeWords - 1]));
            for (i32 BitCountEIndex = (BitCountExponentE - 1);
                 BitCountEIndex >= 0;
                 --BitCountEIndex)
            {
                MontInner(&LocalResult, &LocalResult, &LocalResult, ModulusP, &MinusPInverseModR, RPowerOf2);

                if ((ExponentE->Num[BitCountEIndex/BITS_IN_DWORD] >> (BitCountEIndex % BITS_IN_DWORD)) & 0x1)
                {
                    MontInner(&LocalResult,
                              &LocalResult,
                              &InputXTimesRModP,
                              ModulusP,
                              &MinusPInverseModR,
                              RPowerOf2);
                }
            }

            // return Mont(A, 1)
            InputXTimesRModP.Num[0] = 1;
            InputXTimesRModP.SizeWords = 1;
            MontInner(&LocalResult, &LocalResult, &InputXTimesRModP, ModulusP, &MinusPInverseModR, RPowerOf2);
        }
        else
        {
            LocalResult.SizeWords = 0;
        }

        BigNumCopyUnchecked(OutputA, &LocalResult);
    }
}

internal void
MontModExpRBigNumMax(bignum *OutputA, bignum *InputX, bignum *ExponentE, bignum *ModulusP)
{
    MontModExp(OutputA, InputX, ExponentE, ModulusP, MAX_BIGNUM_SIZE_BITS);
}

internal void
HashSessionKeyGenIvAndEncrypt(u8 *OutputBuffer, u8 *OutputIv, u8 *SessionKey, u32 SessionKeySizeBytes,
                              u8 *Message, u32 MessageLengthBytes, u8 *SessionSymmetricKey)
{
    Stopif((OutputBuffer == 0) || (OutputIv == 0) || (SessionKey == 0) || (SessionSymmetricKey == 0),
           "Null input to HashSessionKeyGenIvAndEncrypt!\n");

    Sha1(SessionSymmetricKey, SessionKey, SessionKeySizeBytes);

    GenRandUnchecked((u32 *)OutputIv, AES_128_BLOCK_LENGTH_WORDS);

    AesCbcEncrypt(OutputBuffer, Message, MessageLengthBytes, SessionSymmetricKey, OutputIv);
}

internal inline void
CopyByteSwappedUnchecked(u8 *Dest, u8 *Source, u32 LengthBytes)
{
    for (u32 SourceIndex = 0;
         SourceIndex < LengthBytes;
         ++SourceIndex)
    {
        Dest[LengthBytes - SourceIndex - 1] = Source[SourceIndex];
    }
}

internal void
CopyPaddedToBigEndianUnchecked(u8 *OutPaddedBigEndian, bignum *Input, u32 PSizeBytes)
{
    u32 InputSizeBytes = BigNumSizeBytesUnchecked(Input);
    Stopif(InputSizeBytes > PSizeBytes, "Invalid Input/PSizeBytes input to CopyPaddedToBigEndianUnchecked!\n");

    u32 PaddingBytes = (PSizeBytes - InputSizeBytes);
    memset(OutPaddedBigEndian, 0, PaddingBytes);

    CopyByteSwappedUnchecked(OutPaddedBigEndian + PaddingBytes, (u8 *)Input->Num, InputSizeBytes);
}

internal void
Sha1PaddedAConcatPaddedB(u8 *OutputHash, u8 *ScratchBuffer, bignum *A, bignum *B, u32 PSizeBytes)
{
    Stopif((OutputHash == 0) || (ScratchBuffer == 0) || (A == 0) || (B == 0),
           "Null input to Sha1PaddedAConcatPaddedB!\n");

    CopyPaddedToBigEndianUnchecked(ScratchBuffer, A, PSizeBytes);

    CopyPaddedToBigEndianUnchecked(ScratchBuffer + PSizeBytes, B, PSizeBytes);

    Sha1(OutputHash, ScratchBuffer, 2*PSizeBytes);
}

internal inline void
HashOutputToBigNumUnchecked(bignum *OutBigNum, u8 *Hash)
{
    OutBigNum->SizeWords = SHA_1_HASH_LENGTH_BYTES/sizeof(u64) + 1;

    memset(OutBigNum->Num, 0, sizeof(u64)*OutBigNum->SizeWords);

    CopyByteSwappedUnchecked((u8 *)OutBigNum->Num, Hash, SHA_1_HASH_LENGTH_BYTES);
}

internal void
SrpGetX(u8 *OutLittleX,
        u8 *Salt,
        u32 SaltLengthBytes,
        u8 *MessageScratch,
        u32 MessageScratchMaxSizeBytes,
        u8 *UserName,
        u32 UserLengthBytes,
        u8 *Password,
        u32 PasswordLengthBytes)
{
    Stopif((OutLittleX == 0) || (Salt == 0) || (MessageScratch == 0), "Null input to SrpGetX!\n");

    u32 EmailPasswordMsgLengthBytes = UserLengthBytes + 1 + PasswordLengthBytes;
    u32 SaltConcatHashEmailPwdLengthBytes = SaltLengthBytes + SHA_1_HASH_LENGTH_BYTES;
    Stopif((SaltConcatHashEmailPwdLengthBytes > MessageScratchMaxSizeBytes) ||
           (EmailPasswordMsgLengthBytes > MessageScratchMaxSizeBytes),
           "MessageScratch buffer overflow in TestImplementSrpTestVec!\n");

    // MessageScratch := SHA1(I | ":" | P)
    memcpy(MessageScratch, UserName, UserLengthBytes);

    MessageScratch[UserLengthBytes] = ':';

    memcpy(MessageScratch + UserLengthBytes + 1,
           Password,
           PasswordLengthBytes);

    Sha1(MessageScratch, MessageScratch, EmailPasswordMsgLengthBytes);

    memmove(MessageScratch + SaltLengthBytes, MessageScratch, SHA_1_HASH_LENGTH_BYTES);

    CopyByteSwappedUnchecked(MessageScratch, Salt, SaltLengthBytes);

    // x := SHA1(s | SHA1(I | ":" | P))
    Sha1(OutLittleX, MessageScratch, SaltConcatHashEmailPwdLengthBytes);
}

internal void
ClientGetPremasterSecret(bignum *OutputSecret,
                         bignum *PrimeModulusN,
                         bignum *Gen,
                         bignum *Salt,
                         bignum *BigB,
                         bignum *LittleA)
{
    Stopif((OutputSecret == 0) ||
           (PrimeModulusN == 0) ||
           (Gen == 0) ||
           (Salt == 0) ||
           (BigB == 0) ||
           (LittleA == 0),
           "Null input to ClientGetPremasterSecret!\n");

    // A := g^a mod N
    bignum BigA;
    MontModExpRBigNumMax(&BigA,
                         (bignum *)&NIST_RFC_5054_GEN_BIGNUM,
                         LittleA,
                         (bignum *)&RFC_5054_NIST_PRIME_1024);

    u32 PSizeBytes = BigNumSizeBytesUnchecked((bignum *)&RFC_5054_NIST_PRIME_1024);
    u8 MessageScratch[2*PSizeBytes];

    // u := SHA1(PAD(A) | PAD(B))
    u8 LittleU[SHA_1_HASH_LENGTH_BYTES];
    Sha1PaddedAConcatPaddedB(LittleU,
                             MessageScratch,
                             &BigA,
                             (bignum *)&RFC_5054_TEST_BIG_B,
                             PSizeBytes);

    // k := SHA1(N | PAD(g))
    u8 LittleK[SHA_1_HASH_LENGTH_BYTES];
    Sha1PaddedAConcatPaddedB(LittleK,
                             MessageScratch,
                             (bignum *)&RFC_5054_NIST_PRIME_1024,
                             (bignum *)&NIST_RFC_5054_GEN_BIGNUM,
                             PSizeBytes);

    u8 LittleX[SHA_1_HASH_LENGTH_BYTES];
    u32 SaltLengthBytes = BigNumSizeBytesUnchecked(Salt);
    SrpGetX(LittleX,
            (u8 *)Salt->Num,
            SaltLengthBytes,
            MessageScratch,
            sizeof(MessageScratch),
            (u8 *)SRP_TEST_VEC_EMAIL,
            STR_LEN(SRP_TEST_VEC_EMAIL),
            (u8 *)SRP_TEST_VEC_PASSWORD,
            STR_LEN(SRP_TEST_VEC_PASSWORD));

    bignum LittleXBigNum;
    HashOutputToBigNumUnchecked(&LittleXBigNum, LittleX);

    // OutputSecret := g^x
    MontModExpRBigNumMax(OutputSecret, Gen, &LittleXBigNum, PrimeModulusN);

    bignum LittleKBigNum;
    HashOutputToBigNumUnchecked(&LittleKBigNum, LittleK);

    Stopif((LittleKBigNum.SizeWords + OutputSecret->SizeWords + 1) > MAX_BIGNUM_SIZE_WORDS,
           "Potential overflow on multiplying k*g^x in TestImplementSrpTestVec!\n");

    // OutputSecret := k * g^x (mod N)
    BigNumMultiplyModP(OutputSecret, &LittleKBigNum, OutputSecret, PrimeModulusN);

    // OutputSecret := (B - (k * g^x))
    BigNumSubtractModP(OutputSecret, BigB, OutputSecret, PrimeModulusN);

    // BigNumScratchExponent := u * x
    bignum LittleUBigNum;
    HashOutputToBigNumUnchecked(&LittleUBigNum, LittleU);

    bignum BigNumScratchExponent;
    BigNumMultiplyOperandScanning(&BigNumScratchExponent, &LittleUBigNum, &LittleXBigNum);

    // BigNumScratchExponent := a + (u * x)
    BigNumAdd(&BigNumScratchExponent, LittleA, &BigNumScratchExponent);

    // OutputSecret := <premaster secret>
    MontModExpRBigNumMax(OutputSecret, OutputSecret, &BigNumScratchExponent, PrimeModulusN);
}

internal void
ServerGetPremasterSecret(bignum *OutSecret, bignum *LittleV, bignum *LittleB, bignum *BigA)
{
    // TODO(bwd): Generate v := g^x mod N
    u8 MessageScratch[2*MEMBER_SIZE(bignum, Num)];
    u8 LittleK[SHA_1_HASH_LENGTH_BYTES];
    u32 PSizeBytes = BigNumSizeBytesUnchecked((bignum *)&RFC_5054_NIST_PRIME_1024);
    Sha1PaddedAConcatPaddedB(LittleK,
                             MessageScratch,
                             (bignum *)&RFC_5054_NIST_PRIME_1024,
                             (bignum *)&NIST_RFC_5054_GEN_BIGNUM,
                             PSizeBytes);

    bignum LittleKBigNum;
    HashOutputToBigNumUnchecked(&LittleKBigNum, LittleK);

    // OutSecret := k*v (mod N)
    BigNumMultiplyModP(OutSecret,
                       &LittleKBigNum,
                       LittleV,
                       (bignum *)&RFC_5054_NIST_PRIME_1024);

    // BigB := g^b
    bignum BigB;
    MontModExpRBigNumMax(&BigB,
                         (bignum *)&NIST_RFC_5054_GEN_BIGNUM,
                         LittleB,
                         (bignum *)&RFC_5054_NIST_PRIME_1024);

    // OutSecret := (k*v + g^b) % N
    BigNumAddModN(OutSecret, OutSecret, &BigB, (bignum *)&RFC_5054_NIST_PRIME_1024);

    u8 LittleU[SHA_1_HASH_LENGTH_BYTES];
    Sha1PaddedAConcatPaddedB(LittleU,
                             MessageScratch,
                             BigA,
                             OutSecret,
                             PSizeBytes);

    bignum LittleUBigNum;
    HashOutputToBigNumUnchecked(&LittleUBigNum, LittleU);

    // OutSecret := v^u (mod N)
    MontModExpRBigNumMax(OutSecret,
                         LittleV,
                         &LittleUBigNum,
                         (bignum *)&RFC_5054_NIST_PRIME_1024);

    // OutSecret := A * v^u (mod N)
    BigNumMultiplyModP(OutSecret, BigA, OutSecret, (bignum *)&RFC_5054_NIST_PRIME_1024);

    // OutSecret := <premaster secret>
    MontModExpRBigNumMax(OutSecret, OutSecret, LittleB, (bignum *)&RFC_5054_NIST_PRIME_1024);
}

internal void
ClientConnectAndGetServerHello(u8 *ClientSendRecvBuffer,
                               u32 ClientBuffMaxSizeBytes,
                               i32 *SocketFileDescriptor,
                               bignum *ModulusN,
                               bignum *LittleG,
                               bignum *Salt,
                               bignum *BigB)
{
    Stopif((ClientSendRecvBuffer == 0) || (SocketFileDescriptor == 0),
           "Null input to ClientConnectAndGetServerHello!");

    sockaddr_in ServerSocketAddr;
    ServerSocketAddr.sin_family = AF_INET;
    ServerSocketAddr.sin_addr.s_addr = inet_addr(IP_ADDRESS);
    ServerSocketAddr.sin_port = htons(PORT);

    OpenSocketAndConnect(SocketFileDescriptor, &ServerSocketAddr);

    write(*SocketFileDescriptor, TEST_USER_COMMAND, TEST_USER_CMD_LENGTH);

    u32 ReadBytes = read(*SocketFileDescriptor, ClientSendRecvBuffer, ClientBuffMaxSizeBytes);
    Stopif(ReadBytes != ClientBuffMaxSizeBytes,
           "Invalid bytes read from (N, g, s ,B) in ClientConnectAndGetServerHello!");

    BigNumCopyUnchecked(ModulusN, (bignum *)ClientSendRecvBuffer);
    BigNumCopyUnchecked(LittleG, (bignum *)ClientSendRecvBuffer + 1);
    BigNumCopyUnchecked(Salt, (bignum *)ClientSendRecvBuffer + 2);
    BigNumCopyUnchecked(BigB, (bignum *)ClientSendRecvBuffer + 3);
}

internal void
PrintArray(u8 *Array, u32 ArrayLengthBytes)
{
    Stopif(Array == 0, "Null input to PrintArray!");

    for (u32 ArrayIndex = 0;
         ArrayIndex < ArrayLengthBytes;
         ++ArrayIndex)
    {
        printf("%02x", Array[ArrayIndex]);
    }

    printf("\n");
}

#endif /* CRYPT_HELPER_H */
