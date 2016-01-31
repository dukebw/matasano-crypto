#include "crypt_helper.h"

u8 GlobalInputBuffer[MAX_BIGNUM_SIZE_BYTES];

int main(int argc, char **argv)
{
    Stopif(argc < 2, "Supply bignum value in argv[1]");

    u8 *InputBigNum = (u8 *)argv[1];
    while (isspace(*InputBigNum))
    {
        ++InputBigNum;
    }

    Stopif((InputBigNum[0] != '0') || (tolower(InputBigNum[1]) != 'x'), "Bad input format (should be hex)");

    InputBigNum += 2;

    u32 InputHexDigitCount = strlen((char *)InputBigNum);
    // Quick hack to force the length to be a multiple of 2
    u32 InputHexDigitsMod2 = (InputHexDigitCount % 2);
    if (InputHexDigitsMod2)
    {
        InputBigNum -= 1;
        InputBigNum[0] = '0';
        ++InputHexDigitCount;
    }

    u32 InputByteCount = InputHexDigitCount/2;
    Stopif(InputByteCount > MAX_BIGNUM_SIZE_BYTES,
           "Input bignum too long (max bytes: %d\n)", MAX_BIGNUM_SIZE_BYTES);

    HexStringToByteArray(GlobalInputBuffer, (char *)InputBigNum, InputHexDigitCount);

    ByteSwap(GlobalInputBuffer, InputByteCount);

    u32 Input64BitWordCount = InputByteCount/sizeof(u64);
    if (InputByteCount % sizeof(u64))
    {
        ++Input64BitWordCount;
    }

    for (u32 Input64BitWordIndex = 0;
         Input64BitWordIndex < Input64BitWordCount;
         ++Input64BitWordIndex)
    {
        printf("0x%lX, ", *(u64 *)(GlobalInputBuffer + sizeof(u64)*Input64BitWordIndex));
    }

    printf("\n");
}
