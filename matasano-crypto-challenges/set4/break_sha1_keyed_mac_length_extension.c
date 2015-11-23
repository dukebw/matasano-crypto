#include "crypt_helper.h"

const u8 ORIGINAL_MESSAGE[] = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
const u8 TEST_KEY[] = "zymosan";
const u8 FORGE_MESSAGE[] = ";admin=true";

internal MIN_UNIT_TEST_FUNC(TestBreakSha1KeyedMacLengthExtension)
{
	u8 ScratchHmac[SHA_1_HASH_LENGTH_BYTES];
	Sha1KeyedMac(ScratchHmac, (u8 *)ORIGINAL_MESSAGE, STR_LEN(ORIGINAL_MESSAGE), (u8 *)TEST_KEY, STR_LEN(TEST_KEY));

	for (u32 OriginalHmacWordIndex = 0;
		 OriginalHmacWordIndex < sizeof(ScratchHmac)/sizeof(u32);
		 ++OriginalHmacWordIndex)
	{
		u32 *NextOrigHmacWord = (u32 *)ScratchHmac + OriginalHmacWordIndex;
		*NextOrigHmacWord = ByteSwap32(*NextOrigHmacWord);
	}

	// We need to add the length of the padded (Key | OriginalMessage) (0x80 -- 1024 bits)
	Sha1InitialValues(ScratchHmac, (u8 *)FORGE_MESSAGE, STR_LEN(FORGE_MESSAGE), ScratchHmac, 0x80);

	u8 TotalForgedInput[STR_LEN(ORIGINAL_MESSAGE) + 1024 + STR_LEN(FORGE_MESSAGE)];
	memcpy(TotalForgedInput, ORIGINAL_MESSAGE, STR_LEN(ORIGINAL_MESSAGE));

	u32 KeyConcatOrigMsgLength = STR_LEN(ORIGINAL_MESSAGE) + STR_LEN(TEST_KEY);
	u32 PaddedMessageLengthWords = (PadSha1((u32 *)(TotalForgedInput - STR_LEN(TEST_KEY)), KeyConcatOrigMsgLength, 0));
	u32 PaddedMessageLengthBytes = sizeof(u32)*PaddedMessageLengthWords - STR_LEN(TEST_KEY);

	u32 *PaddedMsgLastWord = (u32 *)(TotalForgedInput + PaddedMessageLengthBytes - sizeof(u32));
	*PaddedMsgLastWord = ByteSwap32(*PaddedMsgLastWord);
	--PaddedMsgLastWord;
	*PaddedMsgLastWord = ByteSwap32(*PaddedMsgLastWord);

	u32 TotalForgedInputLength = (PaddedMessageLengthBytes + STR_LEN(FORGE_MESSAGE));
	Stopif(TotalForgedInputLength > sizeof(TotalForgedInput),
		   "TotalForgedInput buffer overflow in TestBreakSha1KeyedMacLengthExtension");
	memcpy(TotalForgedInput + PaddedMessageLengthBytes, FORGE_MESSAGE, STR_LEN(FORGE_MESSAGE));

	u8 ExpectedHmac[SHA_1_HASH_LENGTH_BYTES];
	Sha1KeyedMac(ExpectedHmac, TotalForgedInput, TotalForgedInputLength, (u8 *)TEST_KEY, STR_LEN(TEST_KEY));
	MinUnitAssert(VectorsEqual(ExpectedHmac, ScratchHmac, sizeof(ExpectedHmac)),
				  "Expected HMAC vs. actual HMAC mismatch in TestBreakSha1KeyedMacLengthExtension");
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	MinUnitRunTest(TestBreakSha1KeyedMacLengthExtension);
}

int main()
{
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
