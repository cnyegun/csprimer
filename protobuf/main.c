#include <assert.h>
#include <stdint.h>
#include <stdio.h>

typedef uint64_t u64;
typedef uint8_t u8;

static inline int varint_size(u64 src) {
    if (src < (1ULL << 7)) return 1;
    if (src < (1ULL << 14)) return 2;
    if (src < (1ULL << 21)) return 3;
    if (src < (1ULL << 28)) return 4;
    if (src < (1ULL << 35)) return 5;
    if (src < (1ULL << 42)) return 6;
    if (src < (1ULL << 49)) return 7;
    if (src < (1ULL << 56)) return 8;
    if (src < (1ULL << 63)) return 9;
    return 10;
}

int encode(u64 src, u8* dst, u64 len) {
    int bytes_written = varint_size(src);
    if ((u64)bytes_written > len) return bytes_written;

    while (src >= 0x80) {
        *dst++ = (u8)(src | 0x80);
        src >>= 7;
    }

    *dst = (u8)src;
    return bytes_written;
}

int decode(const u8* src, u64* dst) {
    u64 b0 = src[0];
    if ((b0 & 0x80) == 0) {
        *dst = b0;
        return 1;
    }

    u64 result = b0 & 0x7F;

    u64 b1 = src[1];
    result |= (b1 & 0x7F) << 7;
    if ((b1 & 0x80) == 0) {
        *dst = result;
        return 2;
    }

    u64 b2 = src[2];
    result |= (b2 & 0x7F) << 14;
    if ((b2 & 0x80) == 0) {
        *dst = result;
        return 3;
    }

    u64 b3 = src[3];
    result |= (b3 & 0x7F) << 21;
    if ((b3 & 0x80) == 0) {
        *dst = result;
        return 4;
    }

    u64 b4 = src[4];
    result |= (b4 & 0x7F) << 28;
    if ((b4 & 0x80) == 0) {
        *dst = result;
        return 5;
    }

    u64 b5 = src[5];
    result |= (b5 & 0x7F) << 35;
    if ((b5 & 0x80) == 0) {
        *dst = result;
        return 6;
    }

    u64 b6 = src[6];
    result |= (b6 & 0x7F) << 42;
    if ((b6 & 0x80) == 0) {
        *dst = result;
        return 7;
    }

    u64 b7 = src[7];
    result |= (b7 & 0x7F) << 49;
    if ((b7 & 0x80) == 0) {
        *dst = result;
        return 8;
    }

    u64 b8 = src[8];
    result |= (b8 & 0x7F) << 56;
    if ((b8 & 0x80) == 0) {
        *dst = result;
        return 9;
    }

    u64 b9 = src[9];
    result |= b9 << 63;
    *dst = result;
    return 10;
}

static void test_roundtrip(u64 x) {
    u8 buf[10];
    u64 decoded = 0;

    int written = encode(x, buf, sizeof(buf));
    int consumed = decode(buf, &decoded);

    assert(decoded == x);
    assert(consumed == written);
}

int main(void) {
    static const u64 cases[] = {
        0,
        1,
        126,
        127,
        128,
        129,
        (1ULL << 14) - 1,
        1ULL << 14,
        (1ULL << 21) - 1,
        1ULL << 21,
        (1ULL << 28) - 1,
        1ULL << 28,
        (1ULL << 35) - 1,
        1ULL << 35,
        (1ULL << 42) - 1,
        1ULL << 42,
        (1ULL << 49) - 1,
        1ULL << 49,
        (1ULL << 56) - 1,
        1ULL << 56,
        (1ULL << 63) - 1,
        1ULL << 63,
        UINT64_MAX,
    };

    for (u64 i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        test_roundtrip(cases[i]);
    }

    for (u64 i = 0; i < 100000000; i++) {
        test_roundtrip(i);
    }

    printf("All tests passed!\n");
}
