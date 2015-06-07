#include "crypt_helper.h"
#include "crypto/bn/bn.h"

int main()
{
    BN_ULONG SevenArray[] = {7, 1};
    BIGNUM Seven = {
        .d = SevenArray,
        .top = 2,
        .dmax = 2,
        .neg = 0,
        .flags = 2
    };
    BN_ULONG BArray[] = {5, 0xffffffffffffffffL};
    BIGNUM B = {
        .d = BArray,
        .top = 2,
        .dmax = 2,
        .neg = 0,
        .flags = 2
    };

    BIGNUM Sum;
    memset(&Sum, 0, sizeof(Sum));
    if (BN_add(&Sum, &Seven, &B)) {
        printf("Success!\n");
    } else {
        printf("No add!\n");
    }
}
