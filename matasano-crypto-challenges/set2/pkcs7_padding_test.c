#include "min_unit.h"
#include "pkcs7_padding_vector.h"
#include "crypt_helper.h"

global_variable u8 GlobalPkcs7TestScratch[PKCS7_TEST_MAX_MSG_SIZE];

internal b32
Pkcs7PaddingVecsPass(pkcs7_padding_vec *PaddingTestVec, u32 PaddingVecCount)
{
	b32 Result = true;

	Stopif(PaddingTestVec == 0, "Null input to Pkcs7PaddingVecsPass");
	
	for (u32 PaddingTestVecIndex = 0;
		 PaddingTestVecIndex < PaddingVecCount;
		 ++PaddingTestVecIndex, ++PaddingTestVec)
	{
		Pkcs7Pad(GlobalPkcs7TestScratch, PaddingTestVec->Message, PaddingTestVec->MessageLength);
		Result = VectorsEqual(GlobalPkcs7TestScratch,
							  PaddingTestVec->PaddedMessage,
							  PaddingTestVec->PaddedLength);
		if (Result == false)
		{
			break;
		}
	}
	return Result;
}

internal MIN_UNIT_TEST_FUNC(TestPkcs7PaddingVecs)
{
	char *Result = 0;
	Result = MinUnitAssert("Expected/Actual mismatch in Pkcs7PaddingVecsPass()",
						   Pkcs7PaddingVecsPass(Pkcs7PaddingVecs, ArrayLength(Pkcs7PaddingVecs)));
	return Result;
}

int main()
{
	char *Result = TestPkcs7PaddingVecs();
	if (Result)
	{
		printf("Test failed!\n%s\n", Result);
	}
	else
	{
		printf("All tests passed!\n");
	}
}
