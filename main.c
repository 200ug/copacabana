#include "src/uint256.h"

int main() {
    kad_uint256_t a, b, d;

    kad_uint256_random(&a);
    kad_uint256_random(&b);
    kad_uint256_xor(&d, &a, &b);

    kad_uint256_print(&a, "a  ");
    kad_uint256_print(&b, "b  ");
    kad_uint256_print(&d, "xor");

    return 0;
}
