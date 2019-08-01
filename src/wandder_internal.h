



size_t ber_rebuild_integer(uint8_t itemclass, uint32_t idnum, void *valptr, size_t vallen, void* buf);

static inline uint32_t WANDDER_LOG256_SIZE(uint64_t x) {
    if (x < 256) return 1;
    if (x < 65536) return 2;
    if (x < 16777216) return 3;
    if (x < 4294967296) return 4;
    if (x < 1099511627776) return 5;
    if (x < 281474976710656) return 6;
    return floor((log(x) / log(256)) + 1);
}