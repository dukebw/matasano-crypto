#include "crypt_helper.h"

#define MAX_INPUT_PADDED_SIZE 128

const char STRING0[] = "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=";
const char STRING1[] = "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=";
const char STRING2[] = "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==";
const char STRING3[] = "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==";
const char STRING4[] = "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl";
const char STRING5[] = "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==";
const char STRING6[] = "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==";
const char STRING7[] = "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=";
const char STRING8[] = "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=";
const char STRING9[] = "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93";

const char *InputStringArray[] =
{
	STRING0, STRING1, STRING2, STRING3, STRING4, STRING5, STRING6, STRING7, STRING8, STRING9
};
const u32 InputStringLengths[] =
{
	STR_LEN(STRING0), STR_LEN(STRING1), STR_LEN(STRING2), STR_LEN(STRING3), STR_LEN(STRING4),
	STR_LEN(STRING5), STR_LEN(STRING6), STR_LEN(STRING7), STR_LEN(STRING8), STR_LEN(STRING9)
};

// TODO(bwd): Some asserts can move to lower level functions
internal MIN_UNIT_TEST_FUNC(TestPaddingOracleDecrypt)
{
	u32 InputStringIndex = rand() % ARRAY_LENGTH(InputStringArray);
	u32 InputStringLength = InputStringLengths[InputStringIndex];
	u8 InputString[MAX_INPUT_PADDED_SIZE];
	memcpy(InputString, InputStringArray[InputStringIndex], InputStringLength);

	u32 Key[AES_128_BLOCK_LENGTH_WORDS];
	GenRandUnchecked(Key, ARRAY_LENGTH(Key));
	u32 Iv[AES_128_BLOCK_LENGTH_WORDS];
	GenRandUnchecked(Iv, ARRAY_LENGTH(Iv));

	u8 Ciphertext[MAX_INPUT_PADDED_SIZE];
	Stopif(sizeof(Ciphertext) < InputStringLength,
		   "String too long for Ciphertext TestPaddingOracleDecrypt");
	u32 PaddedLength = AesCbcEncrypt(Ciphertext, InputString, InputStringLength,
									 (u8 *)Key, AES_128_BLOCK_LENGTH_BYTES, (u8 *)Iv);
	u32 InputStringLengthMod16 = (InputStringLength % AES_128_BLOCK_LENGTH_BYTES);
	Stopif((PaddedLength < InputStringLength) ||
		   ((InputStringLengthMod16 == 0) &&
			(PaddedLength != (InputStringLength + AES_128_BLOCK_LENGTH_BYTES))) ||
		   ((InputStringLengthMod16 != 0) && (PaddedLength <= InputStringLength)) ||
		   ((PaddedLength % AES_128_BLOCK_LENGTH_BYTES) != 0),
		   "Invalid PaddedLength from AesCbcEncrypt in TestPaddingOracleDecrypt");

	u8 Plaintext[MAX_INPUT_PADDED_SIZE];
	u8 DecryptScratchBuffer[AES_128_BLOCK_LENGTH_BYTES];
	u8 GuessPrevCipherBlock[AES_128_BLOCK_LENGTH_BYTES];
	for (u32 PaddedBlocksIndex = 0;
		 PaddedBlocksIndex < (PaddedLength/AES_128_BLOCK_LENGTH_BYTES);
		 ++PaddedBlocksIndex)
	{
		u32 BlockOffsetInBytes = AES_128_BLOCK_LENGTH_BYTES*PaddedBlocksIndex;
		for (i32 CurrentGuessIndex = (AES_128_BLOCK_LENGTH_BYTES - 1);
			 CurrentGuessIndex >= 0;
			 --CurrentGuessIndex)
		{
			if (PaddedBlocksIndex == 0)
			{
				memcpy(GuessPrevCipherBlock, Iv, AES_128_BLOCK_LENGTH_BYTES);
			}
			else
			{
				memcpy(GuessPrevCipherBlock, Ciphertext + AES_128_BLOCK_LENGTH_BYTES*(PaddedBlocksIndex - 1),
					   AES_128_BLOCK_LENGTH_BYTES);
			}

			u32 CurrentPaddingByteCount = AES_128_BLOCK_LENGTH_BYTES - CurrentGuessIndex;
			for (u32 GuessPaddingByteIndex = CurrentGuessIndex + 1;
				 GuessPaddingByteIndex < AES_128_BLOCK_LENGTH_BYTES;
				 ++GuessPaddingByteIndex)
			{
				GuessPrevCipherBlock[GuessPaddingByteIndex] ^=
					((Plaintext[BlockOffsetInBytes + GuessPaddingByteIndex]) ^ CurrentPaddingByteCount);
			}

			b32 ByteGuessed = false;
			u32 GuessByte;
			for (GuessByte = 0;
				 GuessByte <= 0xFF;
				 ++GuessByte)
			{
				u8 CurrentPaddingByte = LowByte(AES_128_BLOCK_LENGTH_BYTES - CurrentGuessIndex);
				u8 CurrentXorValue = LowByte(GuessByte) ^ CurrentPaddingByte;
				u8 *CurrentXorByte = ((u8 *)GuessPrevCipherBlock + CurrentGuessIndex);
				*CurrentXorByte ^= CurrentXorValue;

				// NOTE(bwd): server padding check
				AesCbcDecrypt(DecryptScratchBuffer,
							  Ciphertext + BlockOffsetInBytes, sizeof(DecryptScratchBuffer),
							  (u8 *)Key, AES_128_BLOCK_LENGTH_BYTES, (u8 *)GuessPrevCipherBlock);

				*CurrentXorByte ^= CurrentXorValue;

				u32 StrippedStringLength;
				u8 *StrippedString = StripPkcs7GetStrippedLength(DecryptScratchBuffer, &StrippedStringLength,
																 AES_128_BLOCK_LENGTH_BYTES);
				if (StrippedString && (StrippedStringLength == (u32)CurrentGuessIndex))
				{
					ByteGuessed = true;
					Plaintext[BlockOffsetInBytes + CurrentGuessIndex] = LowByte(GuessByte);
					break;
				}
			}
			Stopif(!ByteGuessed, "No guess byte found in TestPaddingOracleDecrypt");
		}
		Stopif(memcmp(Plaintext + BlockOffsetInBytes, InputString + BlockOffsetInBytes,
					  AES_128_BLOCK_LENGTH_BYTES) != 0,
			   "Block %d not decrypted correctly", PaddedBlocksIndex);
	}

	MinUnitAssert(memcmp(Plaintext, InputString, InputStringLength) == 0,
				  "Plaintext not recovered in TestPaddingOracleDecrypt");
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	srand(time(0));
	MinUnitRunTest(TestPaddingOracleDecrypt);
}

int main()
{
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
