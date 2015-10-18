#ifndef CRYPT_HELPER_H
#define CRYPT_HELPER_H

#include "allheads.h"
#include "aes.h"
#include "min_unit.h"
#include "compile_assert.h"

CASSERT(RAND_MAX <= UINT32_MAX, crypt_helper_h);

#pragma GCC diagnostic ignored "-Wunused-function"

#define STR_LEN(String) (ARRAY_LENGTH(String) - 1)

#define ALPHABET_SIZE 26

global_variable real32 LetterFrequencies[] =
{
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094,
    0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929,
    0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.02361, 0.00150,
    0.01974, 0.00074
};

internal b32
VectorsEqual(void *A, void *B, u32 Length)
{
	Stopif((A == 0) || (B == 0), "Null input to VectorsEqual");
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

// NOTE(brendan): INPUT: character to shift mod 26, shift amount (assumed to be
// in [0, 25]. OUTPUT: corresponding lower-case character, shifted mod 26
internal u32
ShiftChar(u32 ToShiftChar, u32 ShiftAmount)
{
    // TODO(brendan): more checking
    Stopif(!(((ToShiftChar <= 'Z') && (ToShiftChar >= 'A')) ||
             ((ToShiftChar <= 'z') && (ToShiftChar >= 'a'))),
           "Bad input char");
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
    real32 BestShiftDelta = INFINITY;
 
    for (u32 ShiftAmount = 0; ShiftAmount < ALPHABET_SIZE; ++ShiftAmount)
    {
        for (u32 CipherIndex = 0;
             CipherIndex < CipherLength;
             CipherIndex += KeyLength)
        {
            u32 AlphabetOffset = ShiftChar(Cipher[CipherIndex], ShiftAmount) - 'a';
            ++CharCounts[AlphabetOffset];
        }
        real32 ShiftFrequencySum = 0.0f;
        for (u32 CharIndex = 0; CharIndex < ALPHABET_SIZE; ++CharIndex)
        {
            real32 KeyLetterFreq =
                (real32)CharCounts[CharIndex]/(real32)CipherLength;
            ShiftFrequencySum += KeyLetterFreq*LetterFrequencies[CharIndex];
        }
        real32 ShiftDelta = fabs(ShiftFrequencySum - 0.065);
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
    Stopif(true, "Bad Base64Digit passed to Base64ToUint");
}

internal u32
Base64ToAscii(u8 *AsciiString, u8 *Base64String, u32 Base64StringLength)
{
	Stopif((AsciiString == 0) || (Base64String == 0), "Null input to Base64ToAscii");
	Stopif((Base64StringLength % 4) == 1, "Bad Base64StringLength (ends in 6 bits)");

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
StringToHex(u8 OutHex[], u8 String[], u32 StringLength)
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

inline u32
ByteSwap32(u32 Word)
{
	u32 Result = ((Word << 24) | ((Word & 0xFF00) << 8) |
				  ((Word & 0xFF0000) >> 8) | (Word >> 24));
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
        Stopif(true, "Bad char passed to Base16ToInteger");
    }
	return Result;
}

// NOTE(brendan): INPUT: output string, hex-encoded string. OUTPUT: string
// of characters
internal void
HexStringToByteArray(u8 *Result, char *HexString, u32 Length)
{
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
	Stopif((OutputBuffer == 0) || (FileName == 0), "Null inputs to FileReadIgnoreSpace()");

    FILE *InputFile = fopen(FileName, "r");
    Stopif(!InputFile, "FileRead: No such file");

	u32 ResultSize = fread(OutputBuffer, 1, MaxLength, InputFile);

	fclose(InputFile);

	return ResultSize;
}

internal u32
FileReadIgnoreSpace(u8 *OutputBuffer, char *FileName, u32 MaxLength)
{
	Stopif((OutputBuffer == 0) || (FileName == 0), "Null inputs to FileReadIgnoreSpace()");
    FILE *InputFile = fopen(FileName, "r");
    Stopif(!InputFile, "FileReadIgnoreSpace: No such file");

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
	Stopif(RemainingBytes >= sizeof(u32), "Invalid remaining bytes GenRandBytesUnchecked");

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

	Stopif(Cipher == 0, "Null input to CipherIsEcbEncrypted");

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

	Stopif(Cipher == 0, "Null input to CipherIsEcbEncrypted");

	Result = CipherIsEcbEncryptedBlock(Cipher, CipherLength/AES_128_BLOCK_LENGTH_BYTES);

	return Result;
}

// NOTE(bwd): StrippedStringLength can be 0
// TODO(bwd): better API?
internal u8 *
StripPkcs7GetStrippedLength(u8 *PaddedString, u32 *StrippedStringLengthOut, u32 PaddedStringLength)
{
	u8 *Result = 0;
	Stopif(PaddedString == 0, "Null input to StripPkcs7Padding");
	Stopif((PaddedStringLength % AES_128_BLOCK_LENGTH_BYTES) != 0,
		   "Bad padded length passed to StripPkcs7GetStrippedLength");
	Stopif(PaddedStringLength == 0, "Invalid zero string length passed to StripPkcs7GetStrippedLength");

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

#endif /* CRYPT_HELPER_H */
