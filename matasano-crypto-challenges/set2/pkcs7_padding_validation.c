#include "crypt_helper.h"

internal char *
StripPkcs7Padding(char *PaddedString)
{
	char *Result = 0;
	Stopif(PaddedString == 0, "Null input to StripPkcs7Padding");

	u32 PaddedStringLength = strlen(PaddedString);
	if ((PaddedStringLength % AES_128_BLOCK_LENGTH_BYTES) == 0)
	{
		u8 PaddingBytes = PaddedString[PaddedStringLength - 1];
		if (PaddingBytes < AES_128_BLOCK_LENGTH_BYTES)
		{
			b32 ValidPadding = true;
			char *PaddedBlock = PaddedString + (PaddedStringLength - PaddingBytes);
			for (u32 PaddedBlockIndex = 0;
				 PaddedBlockIndex < PaddingBytes;
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
				*PaddedBlock = 0;
				Result = PaddedString;
			}
		}
	}

	return Result;
}

internal MIN_UNIT_TEST_FUNC(TestPkcs7ValidPadding)
{
	char ValidPkcs7PaddedString[] = "ICE ICE BABY\x04\x04\x04\x04";
	char ExpectedStrippedString[] = "ICE ICE BABY";
	char *StrippedString = StripPkcs7Padding(ValidPkcs7PaddedString);
	MinUnitAssert(!!StrippedString, "Invalid padding returned for valid case!");
	MinUnitAssert((strcmp(StrippedString, ExpectedStrippedString) == 0),
				  "Incorrect string returned for valid case!");
}

internal MIN_UNIT_TEST_FUNC(TestPkcs7InvalidPadding0)
{
	MinUnitAssert(StripPkcs7Padding("ICE ICE BABY\x05\x05\x05\x05") == 0,
				  "Valid PKCS#7 padding found for invalid case 0!");
}

internal MIN_UNIT_TEST_FUNC(TestPkcs7InvalidPadding1)
{
	MinUnitAssert(StripPkcs7Padding("ICE ICE BABY\x01\x02\x03\x04") == 0,
				  "Valid PKCS#7 padding found for invalid case 1!");
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	MinUnitRunTest(TestPkcs7ValidPadding);
	MinUnitRunTest(TestPkcs7InvalidPadding0);
	MinUnitRunTest(TestPkcs7InvalidPadding1);
}

int main()
{
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
