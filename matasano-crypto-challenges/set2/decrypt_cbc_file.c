#include "aes.h"

#define MAX_MSG_LENGTH 4096

global_variable u8 GlobalCbcMessageHex[MAX_MSG_LENGTH];

int main()
{
    u8 CipherBase64[MAX_MSG_LENGTH];
	u32 CipherBase64Length = FileReadIgnoreSpace(CipherBase64, "10.txt", MAX_MSG_LENGTH);
	Stopif(CipherBase64Length == MAX_MSG_LENGTH, return EXIT_FAILURE, "File too long")

    u8 Cipher[MAX_MSG_LENGTH];
    u32 CipherLength = Base64ToAscii(Cipher, CipherBase64, CipherBase64Length);
    Cipher[CipherLength] = 0;

    u8 Key[] = "YELLOW SUBMARINE";
	u8 Iv[AES_128_BLOCK_LENGTH_BYTES] = {0};
	AesCbcDecrypt(GlobalCbcMessageHex, Cipher, CipherLength, Key, AES_128_BLOCK_LENGTH_BYTES, Iv);
    printf("%s\n", GlobalCbcMessageHex);
}
