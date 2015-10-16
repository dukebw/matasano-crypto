#include "min_unit.h"
#include "aes.h"
#include "aes_cbc_mode_vector.h"

global_variable u8 GlobalAesCbcTestScratch[AES_TEST_MAX_MSG_SIZE];

internal b32
AesCbcModeVecsPass(aes_cbc_mode_vec *AesCbcTestVec, u32 AesCbcTestVecCount)
{
	b32 Result = true;

	Stopif(AesCbcTestVec == 0, return false, "Null input to AesCbcModeVecsPass");
	
	for (u32 AesCbcTestVecIndex = 0;
		 AesCbcTestVecIndex < AesCbcTestVecCount;
		 ++AesCbcTestVecIndex, ++AesCbcTestVec)
	{
		aes_test_vector *AesTestVec = &AesCbcTestVec->AesVector;
		Stopif(AesTestVec->MessageLength > AES_TEST_MAX_MSG_SIZE, return false, "Test vector length too large");

		AesCbcEncrypt(GlobalAesCbcTestScratch, AesTestVec->Message, AesTestVec->MessageLength,
					  AesTestVec->Key, AesTestVec->KeyLength, AesCbcTestVec->Iv);
		Result = VectorsEqual(GlobalAesCbcTestScratch, AesTestVec->Cipher, AesTestVec->MessageLength);
		if (Result == false)
		{
			break;
		}

		AesCbcDecrypt(GlobalAesCbcTestScratch, AesTestVec->Cipher, AesTestVec->MessageLength,
					  AesTestVec->Key, AesTestVec->KeyLength, AesCbcTestVec->Iv);
		Result = VectorsEqual(GlobalAesCbcTestScratch, AesTestVec->Message, AesTestVec->MessageLength);
		if (Result == false)
		{
			break;
		}
	}
	return Result;
}

internal MIN_UNIT_TEST_FUNC(TestAesCbcVecs)
{
	MinUnitAssert("Expected/Actual mismatch in AesCbcModeVecsPass()",
				  AesCbcModeVecsPass(GlobalAesCbcVecs, ArrayLength(GlobalAesCbcVecs)));
}

int main()
{
	TestAesCbcVecs();
	printf("All tests passed!\n");
}
