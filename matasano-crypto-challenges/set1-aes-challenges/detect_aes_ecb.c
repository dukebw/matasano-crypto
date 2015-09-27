#include "aes.h"

#define MAX_LINE_LENGTH 4096
#define AES_128_BLOCK_HEX_DIGITS 32
global_variable char GlobalInputBuff[MAX_LINE_LENGTH];

int main()
{
	FILE *InputFile = fopen("8.txt", "r");
	Stopif(!InputFile, return EXIT_FAILURE, "No such file");
	u32 MaxEqualBlocksCount = 0;
	u32 MaxEqualBlocksIndex = 0;
	u32 BlocksEqualCount = 0;
	for (u32 CipherIndex = 0;
		 (fgets(GlobalInputBuff, sizeof(GlobalInputBuff), InputFile) != 0);
		 ++CipherIndex)
	{
		u32 HexDigitCount = strlen(GlobalInputBuff) - 1;

		Stopif((HexDigitCount + 1) >= MAX_LINE_LENGTH, return EXIT_FAILURE, "Input lines too long");
		Stopif((HexDigitCount % (2*AES_128_BLOCK_LENGTH_BYTES)) != 0,
			   return EXIT_FAILURE,
			   "Bad length of input: must be blocks of 16 bytes");
		for (u32 FirstBlockIndex = 0;
			 FirstBlockIndex < (HexDigitCount/AES_128_BLOCK_HEX_DIGITS - 1);
			 ++FirstBlockIndex)
		{
			for (u32 SecondBlockIndex = FirstBlockIndex + 1;
				 SecondBlockIndex < HexDigitCount/AES_128_BLOCK_HEX_DIGITS;
				 ++SecondBlockIndex)
			{
				char *FirstBlock = GlobalInputBuff + FirstBlockIndex*AES_128_BLOCK_HEX_DIGITS;
				char *SecondBlock = GlobalInputBuff + SecondBlockIndex*AES_128_BLOCK_HEX_DIGITS;
				if (memcmp(FirstBlock, SecondBlock, AES_128_BLOCK_HEX_DIGITS) == 0)
				{
					++BlocksEqualCount;
				}
			}
		}

		if (BlocksEqualCount > MaxEqualBlocksCount)
		{
			printf("%s\n", GlobalInputBuff);
			MaxEqualBlocksCount = BlocksEqualCount;
			MaxEqualBlocksIndex = CipherIndex;
		}
	}
	printf("MaxEqualBlocksIndex: %d\n", MaxEqualBlocksIndex);
	printf("BlocksEqualCount: %d\n", BlocksEqualCount);
}
