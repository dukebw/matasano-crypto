#include "crypt_helper.h"
#include "aes_vector.h"

global_variable u8 GlobalScratch[AES_TEST_MAX_MSG_SIZE];

internal b32
AesVectorsPass(aes_test_vector *TestVector, u32 VectorCount)
{
	Stopif(TestVector == 0, "Null input to TestAesVectors");
	b32 Result = true;
	for (u32 TestVecIndex = 0;
		 TestVecIndex < VectorCount;
		 ++TestVecIndex, ++TestVector)
	{
		Stopif(TestVector->MessageLength > AES_TEST_MAX_MSG_SIZE, "Test vector length too large");

		// NOTE(bwd): Test encrypt/decrypt in place
		memcpy(GlobalScratch, TestVector->Message, TestVector->MessageLength);
		AesEcbEncrypt(GlobalScratch, GlobalScratch, TestVector->MessageLength, TestVector->Key);
		Result = VectorsEqual(GlobalScratch, TestVector->Cipher, TestVector->MessageLength);
		if (Result == false)
		{
			break;
		}

		memcpy(GlobalScratch, TestVector->Cipher, TestVector->MessageLength);
		AesEcbDecrypt(GlobalScratch, GlobalScratch, TestVector->MessageLength, TestVector->Key);
		Result = VectorsEqual(GlobalScratch, TestVector->Message, TestVector->MessageLength);
		if (Result == false)
		{
			break;
		}
	}
	return Result;
}

internal MIN_UNIT_TEST_FUNC(TestAesVectors)
{
	MinUnitAssert(AesVectorsPass(GlobalAesVectors, ARRAY_LENGTH(GlobalAesVectors)),
				  "Expected/Actual mismatch in TestVector()");
}

int main()
{
	TestAesVectors();
	printf("All tests passed!\n");
}
