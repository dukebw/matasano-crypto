#include "aes.h"

#define MAX_MSG_LENGTH 65536
#define BLOCK_LEN 16

int main()
{
    u8 CipherBase64[MAX_MSG_LENGTH];
	u32 CipherBase64Length = FileReadIgnoreSpace(CipherBase64, "7.txt", MAX_MSG_LENGTH);
	Stopif(CipherBase64Length == MAX_MSG_LENGTH, return EXIT_FAILURE, "File too long");

    u8 Cipher[MAX_MSG_LENGTH];
    u32 CipherLength = Base64ToAscii(Cipher, CipherBase64, CipherBase64Length);
    Cipher[CipherLength] = 0;

    u8 Key[] = "YELLOW SUBMARINE";
    u32 KeyLength = BLOCK_LEN;

    u8 MessageHex[MAX_MSG_LENGTH];
    for (u32 CipherIndex = 0;
         CipherIndex < CipherLength;
         CipherIndex += BLOCK_LEN)
    {
        AesDecryptBlock(MessageHex + CipherIndex, Cipher + CipherIndex, BLOCK_LEN,
						Key, KeyLength);
    }
    printf("%s\n", MessageHex);
}
