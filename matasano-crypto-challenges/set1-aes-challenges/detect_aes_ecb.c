#define __STDC_WANT_LIB_EXT1__ 1

#include "aes.h"

#define MAX_LINE_LENGTH 65536
global_variable char GlobalInputBuff[MAX_LINE_LENGTH];

int main()
{
	FILE *InputFile = fopen("8.txt", "r");
	Stopif(!InputFile, return EXIT_FAILURE, "No such file");
    for (u8 InputChar;
         (InputChar = fgetc(InputFile)) != (u8)EOF;
         )
	{
		Stopif((strlen(GlobalInputBuff) % 2) != 0,
			   return EXIT_FAILURE,
			   "Number of hex digits read not divisible by 2");
		for (u32 InputStringIndex = 0;
			 GlobalInputBuff[InputStringIndex] != 0;
			 InputStringIndex += 2)
		{
		}
	}
}
