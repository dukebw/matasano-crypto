#include "crypt_helper.h"

internal MIN_UNIT_TEST_FUNC(TestCiphertextModification)
{
	u8 ScratchInput[256];
	u32 TotalInputLength = GenRandInputAppendPrepend(ScratchInput, sizeof(ScratchInput));

	u32 Iv[AES_128_BLOCK_LENGTH_WORDS];
	GenRandUnchecked(Iv, AES_128_BLOCK_LENGTH_WORDS);
	u32 Key[AES_128_BLOCK_LENGTH_WORDS];
	GenRandUnchecked(Key, AES_128_BLOCK_LENGTH_WORDS);

	AesCbcEncrypt(ScratchInput, ScratchInput, TotalInputLength, (u8 *)Key, (u8 *)Iv);

	u8 PlaintextXorAdminTrue[AES_128_BLOCK_LENGTH_BYTES];
	XorVectorsUnchecked(PlaintextXorAdminTrue,
						(u8 *)ADMIN_TRUE_STRING,
						(u8 *)PREPEND_STRING + AES_128_BLOCK_LENGTH_BYTES,
						ADMIN_TRUE_STR_LENGTH);
	XorVectorsUnchecked(ScratchInput, ScratchInput, PlaintextXorAdminTrue, ADMIN_TRUE_STR_LENGTH);

	AesCbcDecrypt(ScratchInput, ScratchInput, TotalInputLength, (u8 *)Key, (u8 *)Iv);

	b32 AdminTrueFound = false;
	for (u32 AdminTrueCheckIndex = 0;
		 AdminTrueCheckIndex <= (TotalInputLength - ADMIN_TRUE_STR_LENGTH);
		 ++AdminTrueCheckIndex)
	{
		if (memcmp(ScratchInput + AdminTrueCheckIndex, ADMIN_TRUE_STRING, ADMIN_TRUE_STR_LENGTH) == 0)
		{
			AdminTrueFound = true;
			break;
		}
	}
	MinUnitAssert(AdminTrueFound, "Ciphertext didn't contain ;admin=true;");
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	srand(time(0));
	MinUnitRunTest(TestCiphertextModification);
}

int main()
{
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
