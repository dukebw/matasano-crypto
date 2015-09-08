#include "aes.h"
#include "min_unit.h"
#include "aes_vector.h"

global_variable u32 GlobalScratch[MAX_MESSAGE_SIZE];

internal b32
TestAesVector(aes_test_vector *TestVector)
{
	Stopif(TestVector == 0, return false, "Null input to TestVector");
	Stopif(TestVector->MessageLength > MAX_MESSAGE_SIZE, return false, "Test vector length too large");
	b32 Result = true;
	AesEncryptBlock((u8 *)GlobalScratch, (u8 *)TestVector->Message,
					sizeof(TestVector->Message[0])*TestVector->MessageLength,
					(u8 *)TestVector->Key, KEY_LENGTH*sizeof(TestVector->Key[0]));
	for (u32 VectorIndex = 0;
		 VectorIndex < TestVector->MessageLength;
		 ++VectorIndex)
	{
		if (GlobalScratch[VectorIndex] != TestVector->Cipher[VectorIndex])
		{
			Result = false;
			break;
		}
	}
	return Result;
}

internal MIN_UNIT_TEST_FUNC(TestAesVector1)
{
	char *Result = 0;
	Result = MinUnitAssert("Expected/Actual mismatch in TestVector()",
						   TestAesVector(&AesVector1));
	return Result;
}

int main()
{
	char *Result = TestAesVector1();
	if (Result)
	{
		printf("Test failed!\n%s\n", Result);
	}
	else
	{
		printf("All tests passed!\n");
	}
}
