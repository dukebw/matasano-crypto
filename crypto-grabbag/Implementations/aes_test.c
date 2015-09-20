#include "aes.h"
#include "min_unit.h"
#include "aes_vector.h"

global_variable u8 GlobalScratch[AES_TEST_MAX_MSG_SIZE];

internal b32
AesVectorsPass(aes_test_vector *TestVector, u32 VectorCount)
{
	Stopif(TestVector == 0, return false, "Null input to TestAesVectors");
	b32 Result = true;
	for (u32 TestVecIndex = 0;
		 TestVecIndex < VectorCount;
		 ++TestVecIndex, ++TestVector)
	{
		Stopif(TestVector->MessageLength > AES_TEST_MAX_MSG_SIZE, return false, "Test vector length too large");

		AesEncryptBlock(GlobalScratch, TestVector->Message, TestVector->MessageLength,
						TestVector->Key, TestVector->KeyLength);
		Result = VectorsEqual(GlobalScratch, TestVector->Cipher, TestVector->MessageLength);
		if (Result == false)
		{
			break;
		}

		AesDecryptBlock(GlobalScratch, TestVector->Cipher, TestVector->MessageLength,
						TestVector->Key, TestVector->KeyLength);
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
	char *Result = 0;
	Result = MinUnitAssert("Expected/Actual mismatch in TestVector()",
						   AesVectorsPass(GlobalAesVectors, ArrayLength(GlobalAesVectors)));
	return Result;
}

int main()
{
	char *Result = TestAesVectors();
	if (Result)
	{
		printf("Test failed!\n%s\n", Result);
	}
	else
	{
		printf("All tests passed!\n");
	}
}
