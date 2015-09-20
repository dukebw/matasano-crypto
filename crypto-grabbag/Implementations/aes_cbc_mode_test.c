#include "min_unit.h"
#include "aes.h"

global_variable u8 GlobalScratch[CBC_TEST_MSG_MAX_SIZE];

internal b32
AesCbcModeVecsPass(aes_cbc_mode_vec *AesCbcTestVec, u32 AesCbcTestVecCount)
{
	b32 Result = true;

	Stopif(AesCbcTestVec == 0, return false, "Null input to AesCbcModeVecsPass");
	
	for (u32 AesCbcTestVecIndex = 0;
		 AesCbcTestVecIndex < AesCbcTestVecCount;
		 ++AesCbcTestVecIndex, ++AesCbcTestVec)
	{
		Stopif(TestVector->MessageLength > AES_TEST_MAX_MSG_SIZE, return false, "Test vector length too large");

		AesCbcEncrypt(GlobalScratch, TestVector->Message, TestVector->MessageLength,
					  TestVector->Key, TestVector->KeyLength, TestVector->Iv);
		Result = VectorsEqual(GlobalScratch, TestVector->Cipher, TestVector->MessageLength);
		if (Result == false)
		{
			break;
		}

		AesCbcDecrypt(GlobalScratch, TestVector->Cipher, TestVector->MessageLength,
					  TestVector->Key, TestVector->KeyLength, TestVector->Iv);
		Result = VectorsEqual(GlobalScratch, TestVector->Message, TestVector->MessageLength);
		if (Result == false)
		{
			break;
		}
	}
	return Result;
}

internal MIN_UNIT_TEST_FUNC(TestAesCbcVecs)
{
	char *Result = 0;
	Result = MinUnitAssert("Expected/Actual mismatch in AesCbcModeVecsPass()",
						   AesCbcModeVecsPass(AesCbcModeVecs, ArrayLength(AesCbcModeVecs)));
	return Result;
}

int main()
{
	char *Result = TestAesCbcVecs();
	if (Result)
	{
		printf("Test failed!\n%s\n", Result);
	}
	else
	{
		printf("All tests passed!\n");
	}
}
