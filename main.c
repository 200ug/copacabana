#include "src/uint256.h"
#include <stdio.h>

int main() {
    kad_uint256_t a, b, d;

    kad_uint256_random(&a);
    kad_uint256_random(&b);
    kad_uint256_xor(&d, &a, &b);

    kad_uint256_print(&a, "a  ");
    kad_uint256_print(&b, "b  ");
    kad_uint256_print(&d, "xor");

    kad_uint256_t target, a_target, b_target;
    kad_uint256_random(&target);
    kad_uint256_print(&target, "\ntarget");

    kad_uint256_xor(&a_target, &a, &target);
    kad_uint256_xor(&b_target, &b, &target);

    // distance comparison example
    int cmp = kad_uint256_cmp(&a_target, &b_target);
    if (cmp < 0) {
        printf("node a is closer to target (smaller xor distance)\n");
    } else if (cmp > 0) {
        printf("node b is closer to target (smaller xor distance)\n");
    } else {
        printf("nodes are equally close to target");
    }

    return 0;
}
