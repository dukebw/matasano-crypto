#include "crypt_helper.h"
#include "aes.h"

#define MAX_MSG_LENGTH 65536
#define BLOCK_LEN 16

int main()
{
    aes_init();

    // TODO(brendan): convert to base 256
    uint8 CipherBase64[MAX_MSG_LENGTH];
    FILE *InputFile = fopen("7.txt", "r");
    Stopif(!InputFile, return EXIT_FAILURE, "No such file");
    uint32 CipherIndex;
    for (CipherIndex = 0;
         (CipherBase64[CipherIndex] = fgetc(InputFile)) != (uint8)EOF;
         ++CipherIndex)
    {
    }

    // TODO(brendan): decrypt!
    uint8 Cipher[MAX_MSG_LENGTH];
    uint32 CipherLength = Base64ToAscii(Cipher, CipherBase64, CipherIndex);
    uint8 CipherHex[MAX_MSG_LENGTH];
    StringToHex(CipherHex, Cipher, CipherLength);

    uint8 Key[] = "YELLOW SUBMARINE";
    uint32 KeyLength = 16;
    uint8 KeyHex[2*KeyLength + 1];
    StringToHex(KeyHex, Key, KeyLength);
    aes_decrypt_ctx Context[1];
    aes_decrypt_key(KeyHex, KeyLength, Context);

    uint8 MessageHex[MAX_MSG_LENGTH];
    aes_decrypt(CipherHex, MessageHex, Context);
    printf("%s\n", MessageHex);

    fclose(InputFile);
}
