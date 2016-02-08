#include "crypt_helper.h"
#include "slre.h"
#include "slre.c"

u8 GlobalInputBuffer[MAX_BIGNUM_SIZE_BYTES];

typedef struct slre_cap slre_cap;

int main(int argc, char **argv)
{
    Stopif(argc < 2, "Supply bignum value in argv[1]!\n");

    slre_cap SlreCaps[2];
    char *InputString = argv[1];
    u32 BytesRead;
    for (BytesRead = 0;
         ;
         BytesRead += SlreCaps[0].len/2)
    {
        i32 MatchedStringLength = slre_match("0x((\\d|[a-f])+)\\s*}?,",
                                             InputString,
                                             strlen(argv[1]),
                                             SlreCaps,
                                             ARRAY_LENGTH(SlreCaps),
                                             SLRE_IGNORE_CASE);
        if (MatchedStringLength > 0)
        {
            Stopif(SlreCaps[0].len % 2, "Invalid hex digit match!\n");

            u8 *NextHexDigit = GlobalInputBuffer + BytesRead;
            HexStringToByteArray(NextHexDigit, (char *)SlreCaps[0].ptr, SlreCaps[0].len);
            ByteSwap(NextHexDigit, SlreCaps[0].len/2);

            InputString += MatchedStringLength;
        }
        else
        {
            break;
        }
    }

    ByteSwap(GlobalInputBuffer, BytesRead);
    PrintArray(GlobalInputBuffer, BytesRead);
}
