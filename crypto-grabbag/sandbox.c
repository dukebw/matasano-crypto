#include "crypt_helper.h"
#include "aes.h"

#define MAX_MSG_LENGTH 65536

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
         ++CipherIndex) {}

    // TODO(brendan): decrypt!
    uint8 Cipher[MAX_MSG_LENGTH];
    Base64ToAscii(Cipher, CipherBase64, CipherIndex);

    uint8 Key[] = "YELLOW SUBMARINE";
    printf("%s\n", Cipher);
    printf("%s\n", Key);
    fclose(InputFile);
}
