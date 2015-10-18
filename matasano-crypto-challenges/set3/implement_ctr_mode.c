#include "crypt_helper.h"

internal MIN_UNIT_TEST_FUNC(TestCtrMode)
{
	const char CTR_CIPHERTEXT[] = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	srand(time(0));
	MinUnitRunTest(TestCtrMode);
}

int main()
{
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
