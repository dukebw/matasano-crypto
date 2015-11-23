#include "crypt_helper.h"
#include "aes_cbc_mode_vector.h"

global_variable u8 GlobalAesCbcTestScratch[AES_TEST_MAX_MSG_SIZE];

internal b32
AesCbcModeVecsPass(aes_cbc_mode_vec *AesCbcTestVec, u32 AesCbcTestVecCount)
{
	b32 Result = true;

	Stopif(AesCbcTestVec == 0, "Null input to AesCbcModeVecsPass");
	
	for (u32 AesCbcTestVecIndex = 0;
		 AesCbcTestVecIndex < AesCbcTestVecCount;
		 ++AesCbcTestVecIndex, ++AesCbcTestVec)
	{
		aes_test_vector *AesTestVec = &AesCbcTestVec->AesVector;
		Stopif(AesTestVec->MessageLength > AES_TEST_MAX_MSG_SIZE, "Test vector length too large");

		// NOTE(bwd): test encrypt/decrypt in place
		memcpy(GlobalAesCbcTestScratch, AesTestVec->Message, AesTestVec->MessageLength);
		AesCbcEncrypt(GlobalAesCbcTestScratch, GlobalAesCbcTestScratch, AesTestVec->MessageLength, AesTestVec->Key,
					  AesCbcTestVec->Iv);
		Result = VectorsEqual(GlobalAesCbcTestScratch, AesTestVec->Cipher, AesTestVec->MessageLength);
		if (Result == false)
		{
			break;
		}

		memcpy(GlobalAesCbcTestScratch, AesTestVec->Cipher, AesTestVec->MessageLength);
		AesCbcDecrypt(GlobalAesCbcTestScratch, GlobalAesCbcTestScratch, AesTestVec->MessageLength, AesTestVec->Key,
					  AesCbcTestVec->Iv);
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
	MinUnitAssert(AesCbcModeVecsPass(GlobalAesCbcVecs, ARRAY_LENGTH(GlobalAesCbcVecs)),
				  "Expected/Actual mismatch in AesCbcModeVecsPass()");
}

int main()
{
	TestAesCbcVecs();
	printf("All tests passed!\n");
}
