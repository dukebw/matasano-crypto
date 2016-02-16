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
    char TempBuffer[16];
    for (BytesRead = 0;
         ;
         BytesRead += BYTES_IN_BIGNUM_WORD)
    {
        i32 MatchedStringLength = slre_match("0x((\\d|[a-f])+)\\s*}?,",
                                             InputString,
                                             strlen(argv[1]),
                                             SlreCaps,
                                             ARRAY_LENGTH(SlreCaps),
                                             SLRE_IGNORE_CASE);
        if (MatchedStringLength > 0)
        {
            u32 HexDigitsInBignum = (2*BYTES_IN_BIGNUM_WORD);

            Stopif(SlreCaps[0].len > (i32)HexDigitsInBignum, "Buffer overflow of TempBuffer!");

            u8 *NextHexDigit = GlobalInputBuffer + BytesRead;

            u32 ZeroBytes;
            if ((SlreCaps[0].len % 2) != 0)
            {
                ZeroBytes = HexDigitsInBignum - SlreCaps[0].len;
                memset(TempBuffer, '0', ZeroBytes);
            }
            else
            {
                ZeroBytes = 0;
            }

            memcpy(TempBuffer + ZeroBytes, SlreCaps[0].ptr, SlreCaps[0].len);

            HexStringToByteArray(NextHexDigit, TempBuffer, HexDigitsInBignum);
            ByteSwap(NextHexDigit, HexDigitsInBignum/2);

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
