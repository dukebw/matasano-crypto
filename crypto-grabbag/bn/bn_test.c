#include "bn.h"

#pragma GCC diagnostic ignored "-Wunused-parameter"

internal void
TestAdd()
{
    big_number BigNumA = {
        .Size = 1,
        .Buffer = {1}
    };
    big_number BigNumB = {
        .Size = 1,
        .Buffer = {0xffffffffffffffffL}
    };
    big_number APlusB;
    BigNumAddMultiPrecision(&APlusB, &BigNumA, &BigNumB);
    g_assert((APlusB.Buffer[1] == 1) && (APlusB.Buffer[0] == 0));
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, (char *)0);
    g_test_add_func("/set1/add test", TestAdd);
    return g_test_run();
}
