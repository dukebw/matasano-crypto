#include "crypt_helper.h"

internal MIN_UNIT_TEST_FUNC(TestCtrMode)
{
	u8 TestKey[] = "YELLOW SUBMARINE";
	u8 Base64CtrCiphertext[] = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";

	u8 CtPtScratch[sizeof(Base64CtrCiphertext)];
	u32 CiphertextLength = Base64ToAscii(CtPtScratch, Base64CtrCiphertext, STR_LEN(Base64CtrCiphertext));

	u8 NonceCounter[AES_128_BLOCK_LENGTH_BYTES] = {0};

	AesCtrMode(CtPtScratch, CtPtScratch, CiphertextLength, TestKey, NonceCounter);

	printf("%s\n", CtPtScratch);

	CtPtScratch[CiphertextLength] = 0;
	u8 ExpectedPlaintext[] = "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby";
	MinUnitAssert(AreVectorsEqual(CtPtScratch, ExpectedPlaintext, STR_LEN(ExpectedPlaintext)),
				  "Expected/Unexpected mismatch in TestCtrMode");
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	MinUnitRunTest(TestCtrMode);
}

int main()
{
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
