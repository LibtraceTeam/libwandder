/*
 *
 * Copyright (c) 2017-2019 The University of Waikato, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This file is part of libwandder.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libwandder is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libwandder is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Shane Alcock
 */

#ifndef LIBWANDDER_INTERNAL_H_
#define LIBWANDDER_INTERNAL_H_

#include <stddef.h>
#include "libwandder.h"


size_t ber_rebuild_integer(uint8_t itemclass, uint32_t idnum, void *valptr, 
        size_t vallen, void* buf);

size_t calculate_length(uint8_t idnum, uint8_t class, uint8_t encodeas, 
        size_t vallen);

size_t encode_here_ber(uint8_t idnum, uint8_t class, uint8_t encodeas, 
        uint8_t* valptr, size_t vallen, uint8_t* ptr, ptrdiff_t rem);

typedef struct etsili_pshdr_diff {    
    ptrdiff_t cin_diff;
    ptrdiff_t seqno_diff;
    ptrdiff_t sec_diff;
    ptrdiff_t usec_diff;
    ptrdiff_t end_diff;
}   etsili_pshdr_diff_t;

static inline uint32_t WANDDER_LOG256_SIZE(uint64_t x) {
    if (x < 256) return 1;
    if (x < 65536) return 2;
    if (x < 16777216) return 3;
    if (x < 4294967296) return 4;
    if (x < 1099511627776) return 5;
    if (x < 281474976710656) return 6;
    return floor((log(x) / log(256)) + 1);
}

static inline int64_t WANDDER_EXTRA_OCTET_THRESH(uint8_t lenocts) {

    if (lenocts == 1) return 128;
    if (lenocts == 2) return 32768;
    if (lenocts == 3) return 8388608;
    if (lenocts == 4) return 2147483648;
    if (lenocts == 5) return 549755813888;
    if (lenocts == 6) return 140737488355328;
    return 36028797018963968;
}
#endif