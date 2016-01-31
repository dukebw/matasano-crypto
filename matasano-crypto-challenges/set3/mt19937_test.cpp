#include <random>
#include "crypt_helper.h"

int main()
{
	std::mt19937 Mt;
	Mt.seed(1234);
	for (u32 StateIndex = 0;
		 StateIndex < 627;
		 ++StateIndex)
	{
		printf("%x\n", Mt());
	}
}
