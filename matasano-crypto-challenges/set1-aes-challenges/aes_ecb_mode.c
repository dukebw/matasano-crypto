#include "aes.h"

#define MAX_MSG_LENGTH 65536
#define BLOCK_LEN 16

int main()
{
    // TODO(brendan): convert to base 256
    u8 CipherBase64[MAX_MSG_LENGTH];
    FILE *InputFile = fopen("7.txt", "r");
    Stopif(!InputFile, return EXIT_FAILURE, "No such file");

    u32 CipherIndex = 0;
    for (u8 InputChar;
         (InputChar = fgetc(InputFile)) != (u8)EOF;
         )
    {
		if (!isspace(InputChar))
		{
			CipherBase64[CipherIndex] = InputChar;
			++CipherIndex;
		}
    }

    // TODO(brendan): decrypt!
    u8 Cipher[MAX_MSG_LENGTH];
    u32 CipherLength = Base64ToAscii(Cipher, CipherBase64, CipherIndex);
    Cipher[CipherLength] = 0;

    u8 Key[] = "YELLOW SUBMARINE";
    u32 KeyLength = BLOCK_LEN;

    // TODO(brendan): decrypt entire message. Decrypt one line at a time?
    u8 MessageHex[MAX_MSG_LENGTH];
    for (u32 CipherIndex = 0;
         CipherIndex < CipherLength;
         CipherIndex += BLOCK_LEN)
    {
        AesDecryptBlock(MessageHex + CipherIndex, Cipher + CipherIndex, BLOCK_LEN,
						Key, KeyLength);
    }
    printf("%s\n", MessageHex);

    fclose(InputFile);
}
