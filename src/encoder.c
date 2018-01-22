/*
 *
 * Copyright (c) 2017 The University of Waikato, Hamilton, New Zealand.
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>
#include "src/libwandder.h"

wandder_encoder_t *init_wandder_encoder(void) {

    wandder_encoder_t *enc = (wandder_encoder_t *)malloc(
            sizeof(wandder_encoder_t));

    enc->pendlist = NULL;
    enc->current = NULL;

}

static void free_pending_r(wandder_pend_t *p) {
    if (p->children) {
        free_pending_r(p->children);
    }

    if (p->siblings) {
        free_pending_r(p->siblings);
    }

    if (p->valspace) {
        free(p->valspace);
    }

    free(p);
}

void reset_wandder_encoder(wandder_encoder_t *enc) {

    /* TODO walk encoding tree and free all items */
    if (enc->pendlist) {
        free_pending_r(enc->pendlist);
    }
    enc->pendlist = NULL;
    enc->current = NULL;
}

void free_wandder_encoder(wandder_encoder_t *enc) {
    reset_wandder_encoder(enc);
    free(enc);
}

static inline wandder_pend_t *new_pending(wandder_pend_t *parent) {
    wandder_pend_t *newp = (wandder_pend_t *)malloc(sizeof(wandder_pend_t));

    newp->identclass = WANDDER_CLASS_UNKNOWN;
    newp->encodeas = WANDDER_TAG_SEQUENCE;
    newp->identifier = 0;
    newp->vallen = 0;
    newp->valspace = NULL;
    newp->children = NULL;
    newp->lastchild = NULL;
    newp->siblings = NULL;
    newp->parent = parent;

    return newp;
}

static uint32_t calc_preamblen(wandder_pend_t *p) {
    uint32_t plen = 0;


    if (p->identifier <= 30) {
        plen += 1;
    } else {
        double log128 = log(p->identifier) / log(128);
        plen += (1 + floor(log128 + 1));
    }

    if (p->vallen < 128) {
        plen += 1;
    } else {
        double log256 = log(p->vallen) / log(256);
        plen += (1 + floor(log256 + 1));
    }
    return plen;
}

static uint32_t encode_identifier(uint8_t class, uint32_t ident,
        uint8_t *buf, uint32_t rem) {

    uint8_t encarray[8];
    uint8_t ind = 0;
    int i = 0;

    if (class == WANDDER_CLASS_UNKNOWN) {
        fprintf(stderr, "Encode error: class was unknown\n");
        return 0;
    }

    if (ident <= 30) {
        /* Single byte identifier */
        *buf = (uint8_t)((class << 5) | ident);
        return 1;
    }

    if (rem == 0) {
        fprintf(stderr, "Encode error: no more space while encoding identifier\n");
        return 0;
    }

    *buf = (uint8_t)((class << 5) | 0x1f);
    buf += 1;
    rem -= 1;

    while (ident > 0) {
        encarray[ind] = (ident & 0x7f);
        ident = ident >> 7;
        ind += 1;
    }

    for (i = ind - 1; i >= 0; i--) {
        if (rem == 0) {
            fprintf(stderr, "Encode error: no more space while encoding identifier\n");
            return 0;
        }

        if (i > 0) {
            *buf = (0x80 | encarray[ind]);
        } else {
            *buf = encarray[ind];
        }

        buf += 1;
        rem -= 1;
    }

    return ind + 1;
}

static uint32_t encode_length(uint32_t len, uint8_t *buf, uint32_t rem) {

    uint8_t lenocts = 0;
    uint8_t encarray[128];
    uint8_t ind = 0;
    int i = 0;

    if (rem == 0) {
        fprintf(stderr, "Encode error: no more space while encoding length\n");
        return 0;
    }

    if (len < 128) {
        *buf = (uint8_t)len;
        return 1;
    }

    lenocts = floor((log(len) / log(256)) + 1);
    *buf = (uint8_t)(lenocts | 0x80);

    buf += 1;
    rem -= 1;

    while (len > 0) {
        encarray[ind] = (len & 0xff);
        len = len >> 8;
        ind += 1;
    }

    for (i = ind - 1; i >= 0; i--) {
        if (rem == 0) {
            fprintf(stderr, "Encode error: no more space while encoding length\n");
            return 0;
        }

        *buf = encarray[i];
        buf += 1;
        rem -= 1;
    }

    return ind + 1;

}

static uint32_t encode_oid(wandder_pend_t *p, void *valptr, uint32_t len) {

    uint8_t *ptr;
    uint8_t *cast = (uint8_t *)valptr;

    if (len < 2) {
        fprintf(stderr, "Encode error: OID is too short!\n");
        return 0;
    }

    p->valspace = (uint8_t *)malloc(len - 1);
    p->vallen = len - 1;

    ptr = p->valspace;
    *ptr = (40 * cast[0]) + cast[1];
    ptr += 1;

    memcpy(ptr, cast + 2, len - 2);
    return len - 1;
}

static uint32_t encode_integer(wandder_pend_t *p, void *valptr, uint32_t len) {

    int64_t val;
    uint8_t lenocts;
    uint8_t encarray[8];
    uint8_t *ptr;
    int i;

    if (len == 8) {
        val = *((int64_t *)valptr);
    } else if (len == 4) {
        val = *((int32_t *)valptr);
    } else {
        fprintf(stderr, "Encode error: unexpected length for integer type: %u\n",
                len);
        return 0;
    }

    lenocts = floor((log(val) / log(256)) + 1);
    if (lenocts == 0) {
        lenocts = 1;
    }

    for (i = 0; i < lenocts; i++) {
        encarray[i] = (val & 0xff);
        val = val >> 8;
    }

    p->valspace = (uint8_t *) malloc(lenocts);
    p->vallen = lenocts;

    ptr = p->valspace;
    for (i = lenocts - 1; i >= 0; i--) {
        *ptr = encarray[i];
        ptr += 1;
    }

    return lenocts;
}

static uint32_t encode_gtime(wandder_pend_t *p, void *valptr, uint32_t len) {

    struct timeval *tv = (struct timeval *)valptr;
    struct tm tm;
    time_t tstamp;
    char gtimebuf[1024];
    char timebuf[768];
    int towrite = 0;

    if (len != sizeof(struct timeval)) {
        fprintf(stderr, "Encode error: unexpected length for timeval: %u\n",
                len);
        return 0;
    }

    tstamp = tv->tv_sec;
    if (gmtime_r(&tstamp, &tm) == NULL) {
        fprintf(stderr, "Encode error: failed to convert timeval to tm\n");
        return 0;
    }

    strftime(timebuf, 768, "%Y%m%d%H%M%S", &tm);
    snprintf(gtimebuf, 1024, "%s.%03dZ", timebuf, tv->tv_usec / 1000);
    towrite = strlen(gtimebuf);

    p->valspace = (uint8_t *)malloc(towrite);
    p->vallen = towrite;

    memcpy(p->valspace, gtimebuf, towrite);
    return (uint32_t)towrite;
}

static uint32_t encode_value(wandder_pend_t *p, void *valptr, uint32_t vallen) {

    switch(p->encodeas) {
        case WANDDER_TAG_OCTETSTRING:
        case WANDDER_TAG_UTF8STR:
        case WANDDER_TAG_NUMERIC:
        case WANDDER_TAG_PRINTABLE:
        case WANDDER_TAG_IA5:
        case WANDDER_TAG_RELATIVEOID:
            p->valspace = (uint8_t *)malloc(vallen);
            memcpy(p->valspace, valptr, vallen);
            p->vallen = vallen;
            break;

        case WANDDER_TAG_GENERALTIME:
            /* Timeval to general TS */
            if (encode_gtime(p, valptr, vallen) == 0) {
                return 0;
            }
            break;
        case WANDDER_TAG_INTEGER:
            /* Signed int to Integer */
            if (encode_integer(p, valptr, vallen) == 0) {
                return 0;
            }
            break;

        case WANDDER_TAG_OID:
            /* Byte array to OID */
            if (encode_oid(p, valptr, vallen) == 0) {
                return 0;
            }
            break;

        case WANDDER_TAG_NULL:
        case WANDDER_TAG_SEQUENCE:
        case WANDDER_TAG_SET:
            break;

        case WANDDER_TAG_IPPACKET:
            p->vallen = vallen;
            p->valspace = NULL;
            break;

        default:
            fprintf(stderr, "Encode error: unable to encode tag type %d\n",
                    p->encodeas);
            return 0;
    }

}

void wandder_encode_next(wandder_encoder_t *enc, uint8_t encodeas,
        uint8_t itemclass, uint32_t idnum, void *valptr, uint32_t vallen) {

    if (enc->pendlist == NULL) {
        /* First item */
        enc->pendlist = new_pending(NULL);
        enc->current = enc->pendlist;
    } else if (IS_CONSTRUCTED(enc->current) && enc->current->children == NULL) {
        wandder_pend_t *next = new_pending(enc->current);
        enc->current->children = next;
        enc->current->lastchild = next;
        enc->current = next;
    } else {
        /* Must be a sibling */
        wandder_pend_t *next = new_pending(enc->current->parent);
        enc->current->siblings = next;
        enc->current->parent->lastchild = next;
        enc->current = next;
    }

    enc->current->identclass = itemclass;
    enc->current->identifier = idnum;
    enc->current->encodeas = encodeas;
    if (valptr != NULL && vallen > 0) {
        encode_value(enc->current, valptr, vallen);
    } else {
        enc->current->valspace = NULL;
        enc->current->vallen = 0;
    }

}


void wandder_encode_endseq(wandder_encoder_t *enc) {

    wandder_pend_t *p = NULL;
    uint32_t totallen = 0;

    if (enc->current->parent == NULL) {
        return;
    }

    enc->current = enc->current->parent;

    /* All children are complete, can calculate length for parent */
    p = enc->current->children;
    while (p != NULL) {
        totallen += (p->vallen + calc_preamblen(p));
        p = p->siblings;
    }

    enc->current->vallen = totallen;
}

uint32_t encode_r(wandder_pend_t *p, uint8_t *buf, uint32_t rem) {
    uint32_t ret;
    uint32_t tot = 0;

    ret = encode_identifier(p->identclass, p->identifier, buf, rem);

    if (ret == 0) {
        return 0;
    }

    buf += ret;
    rem -= ret;
    tot += ret;

    ret = encode_length(p->vallen, buf, rem);

    if (ret == 0) {
        return 0;
    }

    buf += ret;
    rem -= ret;
    tot += ret;

    if (p->children) {
        ret = encode_r(p->children, buf, rem);
        if (ret == 0) {
            return 0;
        }
        buf += ret;
        rem -= ret;
        tot += ret;
    }

    if (p->valspace != NULL) {
        if (rem < p->vallen) {
            fprintf(stderr, "Encode error: not enough space for value\n");
            return 0;
        }

        memcpy(buf, p->valspace, p->vallen);

        buf += p->vallen;
        rem -= p->vallen;
        tot += p->vallen;
    }

    if (p->siblings) {
        ret = encode_r(p->siblings, buf, rem);
        if (ret == 0) {
            return 0;
        }
        return ret + tot;
    }

    return tot;
}

uint8_t *wandder_encode_finish(wandder_encoder_t *enc, uint32_t *len) {

    uint8_t *result = NULL;

    *len = enc->pendlist->vallen + calc_preamblen(enc->pendlist);
    result = (uint8_t *)calloc(1, *len);

    if (encode_r(enc->pendlist, result, *len) == 0) {
        fprintf(stderr, "Failed to encode wandder structure\n");
        free(result);
        return NULL;
    }

    return result;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
