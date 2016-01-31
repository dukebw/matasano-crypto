#include "crypt_helper.h"

internal MIN_UNIT_TEST_FUNC(TestPkcs7ValidPadding)
{
	u8 ValidPkcs7PaddedString[] = "ICE ICE BABY\x04\x04\x04\x04";
	u8 ExpectedStrippedString[] = "ICE ICE BABY";
	u8 *StrippedString = StripPkcs7Padding((u8 *)ValidPkcs7PaddedString, STR_LEN(ValidPkcs7PaddedString));
	MinUnitAssert(!!StrippedString, "Invalid padding returned for valid case!");
	MinUnitAssert((memcmp(StrippedString, ExpectedStrippedString, STR_LEN(ExpectedStrippedString)) == 0),
				  "Incorrect string returned for valid case!");
}

internal MIN_UNIT_TEST_FUNC(TestPkcs7InvalidPadding0)
{
	u8 InvalidPkcs7Padded[] = "ICE ICE BABY\x05\x05\x05\x05";
	MinUnitAssert(StripPkcs7Padding(InvalidPkcs7Padded, STR_LEN(InvalidPkcs7Padded)) == 0,
				  "Valid PKCS#7 padding found for invalid case 0!");
}

internal MIN_UNIT_TEST_FUNC(TestPkcs7InvalidPadding1)
{
	u8 InvalidPkcs7Padded[] = "ICE ICE BABY\x01\x02\x03\x04";
	MinUnitAssert(StripPkcs7Padding(InvalidPkcs7Padded, STR_LEN(InvalidPkcs7Padded)) == 0,
				  "Valid PKCS#7 padding found for invalid case 1!");
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	MinUnitRunTest(TestPkcs7ValidPadding);
	MinUnitRunTest(TestPkcs7InvalidPadding0);
	MinUnitRunTest(TestPkcs7InvalidPadding1);
}

int main()
{
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
