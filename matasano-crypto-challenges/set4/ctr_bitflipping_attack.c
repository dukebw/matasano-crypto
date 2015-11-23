#include "crypt_helper.h"

internal MIN_UNIT_TEST_FUNC(TestCtrCtModification)
{
	u8 ScratchInput[256];
	u32 TotalInputLength = GenRandInputAppendPrepend(ScratchInput, sizeof(ScratchInput));

	u8 NonceCounter[AES_128_BLOCK_LENGTH_BYTES] = {0};
	u32 Key[AES_128_BLOCK_LENGTH_WORDS];
	GenRandUnchecked(Key, AES_128_BLOCK_LENGTH_WORDS);

	AesCtrMode(ScratchInput, ScratchInput, TotalInputLength, (u8 *)Key, NonceCounter);

	u8 PlaintextXorAdminTrue[AES_128_BLOCK_LENGTH_BYTES];
	XorVectorsUnchecked(PlaintextXorAdminTrue, (u8 *)ADMIN_TRUE_STRING, (u8 *)PREPEND_STRING, ADMIN_TRUE_STR_LENGTH);
	XorVectorsUnchecked(ScratchInput, ScratchInput, PlaintextXorAdminTrue, ADMIN_TRUE_STR_LENGTH);

	memset(NonceCounter, 0, sizeof(NonceCounter));
	AesCtrMode(ScratchInput, ScratchInput, TotalInputLength, (u8 *)Key, NonceCounter);

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
	MinUnitRunTest(TestCtrCtModification);
}

int main()
{
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
