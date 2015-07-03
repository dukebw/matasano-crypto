#include "crypt_helper.h"
#include "aes.h"

#define MAX_MSG_LENGTH 65536
#define BLOCK_LEN 16

int main()
{
    aes_init();

    // TODO(brendan): convert to base 256
    uint8 CipherBase64[MAX_MSG_LENGTH];
    FILE *InputFile = fopen("7_no_space.txt", "r");
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
    Cipher[CipherLength] = 0;

    uint8 Key[] = "YELLOW SUBMARINE";
    uint32 KeyLength = 16;
    aes_decrypt_ctx Context[1];
    aes_decrypt_key(Key, KeyLength, Context);

    // TODO(brendan): decrypt entire message. Decrypt one line at a time?
    uint8 MessageHex[MAX_MSG_LENGTH];
    for (uint32 CipherIndex = 0;
         CipherIndex < CipherLength;
         CipherIndex += 16)
    {
        aes_decrypt(Cipher + CipherIndex, MessageHex + CipherIndex, Context);
    }
    printf("%s\n", MessageHex);

    fclose(InputFile);
}
