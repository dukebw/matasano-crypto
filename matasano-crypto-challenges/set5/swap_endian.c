#include "crypt_helper.h"
#include "slre.h"
#include "slre.c"

typedef struct slre_cap slre_cap;

int main(int argc, char **argv)
{
    Stopif(argc < 2, "Supply bignum value in argv[1]!\n");

    slre_cap SlreCaps[3];
    u8 InputBuffer[128];

    i32 MatchedStringLength = slre_match("((\\d|[a-f])*)",
                                         argv[1],
                                         strlen(argv[1]),
                                         SlreCaps,
                                         ARRAY_LENGTH(SlreCaps),
                                         SLRE_IGNORE_CASE);
    if (MatchedStringLength > 0)
    {
        Stopif(SlreCaps[0].len % 2, "Invalid hex digit match!\n");

        HexStringToByteArray(InputBuffer, (char *)SlreCaps[0].ptr, SlreCaps[0].len);

        u32 InputBuffLengthBytes = MatchedStringLength/2;
        ByteSwap(InputBuffer, InputBuffLengthBytes);

        for (u32 ArrayIndex = 0;
             ArrayIndex < InputBuffLengthBytes;
             ++ArrayIndex)
        {
            printf("0x%02x, ", InputBuffer[ArrayIndex]);
        }

        printf("\n");
    }
}
