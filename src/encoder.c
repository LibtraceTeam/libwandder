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

#define VALALLOC(x, p) \
    if (x > p->valalloced) { \
        if (x < 512) { \
            p->valspace = (uint8_t *)realloc(p->valspace, 512); \
            p->valalloced = 512; \
        } else { \
            p->valspace = (uint8_t *)realloc(p->valspace, (x)); \
            p->valalloced = x; \
        }\
    }

wandder_encoder_t *init_wandder_encoder(void) {

    wandder_encoder_t *enc = (wandder_encoder_t *)calloc(1,
            sizeof(wandder_encoder_t));

    pthread_mutex_init(&(enc->mutex), NULL);
    return enc;
}

static inline void free_single_pending(wandder_pend_t **freelist,
        wandder_pend_t *p) {

    p->lastchild = NULL;
    p->siblings = NULL;
    p->parent = NULL;
    p->children = NULL;
    p->nextfree = *freelist;
    *freelist = p;
}

void reset_wandder_encoder(wandder_encoder_t *enc) {
    wandder_pend_t *p, *tmp, *savedsib;

    if (enc->quickfree_tail) {
        enc->quickfree_tail->nextfree = enc->freelist;
        enc->freelist = enc->quickfree_head;
    }

    if (enc->quickfree_pc_tail) {
        enc->quickfree_pc_tail->nextfree = enc->freeprecompute;
        enc->freeprecompute = enc->quickfree_pc_head;
    }


    enc->quickfree_tail = NULL;
    enc->quickfree_head = NULL;
    enc->quickfree_pc_tail = NULL;
    enc->quickfree_pc_head = NULL;
    enc->pendlist = NULL;
    enc->current = NULL;
}

void free_wandder_encoder(wandder_encoder_t *enc) {
    wandder_pend_t *p, *tmp;
    wandder_encoded_result_t *res, *restmp;

    reset_wandder_encoder(enc);
    p = enc->freelist;
    while (p) {
        tmp = p;
        p = p->nextfree;
        free(tmp->thisjob.valspace);
        free(tmp);
    }

    p = enc->freeprecompute;
    while (p) {
        tmp = p;
        p = p->nextfree;
        free(tmp);
    }

    pthread_mutex_lock(&(enc->mutex));
    res = enc->freeresults;
    while (res) {
        restmp = res;
        res = res->next;
        free(restmp->encoded);
        free(restmp);
    }
    pthread_mutex_unlock(&(enc->mutex));

    pthread_mutex_destroy(&(enc->mutex));
    free(enc);
}

static inline wandder_pend_t *new_pending(wandder_encoder_t *enc,
        wandder_encode_job_t *job, wandder_pend_t *parent) {
    wandder_pend_t *newp;

    if (!job) {
        if (enc->freelist) {
            newp = enc->freelist;
            enc->freelist = newp->nextfree;
            newp->nextfree = NULL;
            newp->lastchild = NULL;
            newp->siblings = NULL;
            newp->parent = NULL;
            newp->children = NULL;
        } else {
            newp = (wandder_pend_t *)calloc(1, sizeof(wandder_pend_t));
        }

        if (!enc->quickfree_tail) {
            enc->quickfree_tail = newp;
            enc->quickfree_head = newp;
            newp->nextfree = NULL;
        } else {
            newp->nextfree = enc->quickfree_head;
            enc->quickfree_head = newp;
        }
    } else {
        if (enc->freeprecompute) {
            newp = enc->freeprecompute;
            enc->freeprecompute = newp->nextfree;
            newp->nextfree = NULL;
            newp->lastchild = NULL;
            newp->siblings = NULL;
            newp->parent = NULL;
            newp->children = NULL;
        } else {
            newp = (wandder_pend_t *)calloc(1, sizeof(wandder_pend_t));
            if (job->vallen == 0) {
                job->preamblen = 0;
            }
        }

        newp->thisjob.identclass = job->identclass;
        newp->thisjob.identifier = job->identifier;
        newp->thisjob.encodeas = job->encodeas;
        newp->thisjob.encodedspace = job->encodedspace;
        newp->thisjob.encodedlen = job->encodedlen;

        if (!enc->quickfree_pc_tail) {
            enc->quickfree_pc_tail = newp;
            enc->quickfree_pc_head = newp;
            newp->nextfree = NULL;
        } else {
            newp->nextfree = enc->quickfree_pc_head;
            enc->quickfree_pc_head = newp;
        }
    }

    newp->parent = parent;
    newp->childrensize = 0;

    return newp;
}

static inline uint32_t WANDDER_LOG128_SIZE(uint64_t x) {
    if (x < 128) return 1;
    if (x < 16383) return 2;
    return floor((log(x) / log(128)) + 1);
}

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

static inline uint32_t calc_preamblen(uint32_t identifier, uint32_t len) {
    uint32_t plen = 0;
    uint32_t loglen = 0;

    if (identifier <= 30) {
        plen += 1;
    } else {
        loglen = WANDDER_LOG128_SIZE(identifier);
        plen += (1 + loglen);
    }

    if (len < 128) {
        plen += 1;
    } else {
        loglen = WANDDER_LOG256_SIZE(len);
        plen += (1 + loglen);

        if (len > WANDDER_EXTRA_OCTET_THRESH(loglen)) {
            plen ++;
        }
    }

    return plen;
}

static inline uint32_t encode_identifier_fast(uint8_t class, uint32_t ident,
        uint8_t *buf) {

    /* Single byte identifier */
    *buf = (uint8_t)((class << 5) | ident);
    return 1;
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

static inline uint32_t encode_length(uint32_t len, uint8_t *buf, uint32_t rem) {
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

    lenocts = WANDDER_LOG256_SIZE(len);
    if (len > WANDDER_EXTRA_OCTET_THRESH(lenocts)) {
        lenocts ++;
    }

    *buf = lenocts | 0x80;

    buf += 1;
    rem -= 1;

    if (rem < lenocts) {
        fprintf(stderr, "Not enough bytes left to encode length field\n");
        return 0;
    }

    for (i = lenocts - 1; i >= 0; i--) {
        *(buf + i) = (len & 0xff);
        len = len >> 8;
    }

    return lenocts + 1;

}

static uint32_t encode_oid(wandder_encode_job_t *p, void *valptr,
        uint32_t len) {

    uint8_t *ptr;
    uint8_t *cast = (uint8_t *)valptr;

    if (len < 2) {
        fprintf(stderr, "Encode error: OID is too short!\n");
        return 0;
    }

    VALALLOC((len - 1), p);
    p->vallen = len - 1;
    ptr = p->valspace;
    *ptr = (40 * cast[0]) + cast[1];
    ptr += 1;

    memcpy(ptr, cast + 2, len - 2);
    return len - 1;
}

static inline uint32_t encode_integer(wandder_encode_job_t *p, void *valptr,
        uint32_t len) {

    int64_t val;
    uint8_t lenocts;
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

    if (val < 0) {
        /* Play it safe with negative numbers (or seemingly negative ones) */
        lenocts = len;
    } else {
        lenocts = WANDDER_LOG256_SIZE(val);
        if (lenocts == 0) {
            lenocts = 1;
        }

        if (lenocts > 7) {
            lenocts = len;
        }
        if (lenocts < len && val >= WANDDER_EXTRA_OCTET_THRESH(lenocts)) {
            lenocts ++;
        }
    }

    VALALLOC(lenocts, p);
    p->vallen = lenocts;
    ptr = p->valspace;

    for (i = lenocts - 1; i >= 0; i--) {
        ptr[i] = (val & 0xff);
        val = val >> 8;
    }

    return lenocts;
}

static uint32_t encode_gtime(wandder_encode_job_t *p, void *valptr,
        uint32_t len) {

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
    snprintf(gtimebuf, 1024, "%s.%03ldZ", timebuf,
            (int64_t)(tv->tv_usec / 1000));
    towrite = strlen(gtimebuf);

    VALALLOC(towrite, p);
    p->vallen = towrite;

    memcpy(p->valspace, gtimebuf, towrite);
    return (uint32_t)towrite;
}

static inline uint32_t save_value_to_encode(wandder_encode_job_t *job, void *valptr,
        uint32_t vallen) {

    switch(job->encodeas) {
        case WANDDER_TAG_OCTETSTRING:
        case WANDDER_TAG_UTF8STR:
        case WANDDER_TAG_NUMERIC:
        case WANDDER_TAG_PRINTABLE:
        case WANDDER_TAG_IA5:
        case WANDDER_TAG_RELATIVEOID:
            VALALLOC(vallen, job);
            memcpy(job->valspace, valptr, vallen);
            job->vallen = vallen;
            job->preamblen = calc_preamblen(job->identifier, vallen);
            break;

        case WANDDER_TAG_GENERALTIME:
            /* Timeval to general TS */
            if (encode_gtime(job, valptr, vallen) == 0) {
                return 0;
            }
            job->preamblen = calc_preamblen(job->identifier, vallen);
            break;
        case WANDDER_TAG_INTEGER:
        case WANDDER_TAG_ENUM:
            /* Signed int to Integer */
            if (encode_integer(job, valptr, vallen) == 0) {
                return 0;
            }
            job->preamblen = calc_preamblen(job->identifier, vallen);
            break;

        case WANDDER_TAG_OID:
            /* Byte array to OID */
            if (encode_oid(job, valptr, vallen) == 0) {
                return 0;
            }
            job->preamblen = calc_preamblen(job->identifier, vallen);
            break;


        case WANDDER_TAG_NULL:
        case WANDDER_TAG_SEQUENCE:
        case WANDDER_TAG_SET:
            job->vallen = 0;
            job->preamblen = 0;
            break;

        case WANDDER_TAG_IPPACKET:
            job->vallen = vallen;
            job->preamblen = calc_preamblen(job->identifier, vallen);
            break;

        default:
            fprintf(stderr, "Encode error: unable to encode tag type %d\n",
                    job->encodeas);
            return 0;
    }
}

void wandder_encode_next(wandder_encoder_t *enc, uint8_t encodeas,
        uint8_t itemclass, uint32_t idnum, void *valptr, uint32_t vallen) {

    wandder_encode_job_t *job = &(enc->current->thisjob);

    if (enc->pendlist == NULL) {
        /* First item */
        enc->pendlist = new_pending(enc, NULL, NULL);
        enc->current = enc->pendlist;
    } else if (IS_CONSTRUCTED(job) &&
            enc->current->children == NULL) {
        wandder_pend_t *next = new_pending(enc, NULL, enc->current);
        enc->current->children = next;
        enc->current->lastchild = next;
        enc->current = next;
    } else {
        /* Must be a sibling */
        wandder_pend_t *next = new_pending(enc, NULL, enc->current->parent);
        enc->current->siblings = next;
        enc->current->parent->lastchild = next;
        enc->current = next;
    }

    enc->current->thisjob.identclass = itemclass;
    enc->current->thisjob.identifier = idnum;
    enc->current->thisjob.encodeas = encodeas;
    if (valptr != NULL && vallen > 0) {
        save_value_to_encode(&(enc->current->thisjob), valptr, vallen);
        if (enc->current->parent) {
            enc->current->parent->childrensize +=
                (enc->current->thisjob.vallen +
                 enc->current->thisjob.preamblen);
        }
    } else {
        enc->current->thisjob.vallen = 0;
    }

}

void wandder_encode_next_preencoded(wandder_encoder_t *enc,
        wandder_encode_job_t **jobs, int jobcount) {

    int i;
    for (i = 0; i < jobcount; i++) {
        wandder_encode_job_t *thisjob = &(enc->current->thisjob);
        wandder_encode_job_t *job = jobs[i];

        if (enc->pendlist == NULL) {
            /* First item */
            enc->pendlist = new_pending(enc, job, NULL);
            enc->current = enc->pendlist;
        } else if (IS_CONSTRUCTED(thisjob) &&
                enc->current->children == NULL) {
            wandder_pend_t *next = new_pending(enc, job, enc->current);
            enc->current->children = next;
            enc->current->lastchild = next;
            enc->current = next;
        } else {
            /* Must be a sibling */
            wandder_pend_t *next = new_pending(enc, job, enc->current->parent);
            enc->current->siblings = next;
            enc->current->parent->lastchild = next;
            enc->current = next;
        }

        if (enc->current->parent) {
            enc->current->parent->childrensize +=
                    enc->current->thisjob.encodedlen;
        }
    }

    /*
    printf("P %u %u %u %u %u\n", enc->current->thisjob.identclass,
            enc->current->thisjob.identifier,
            enc->current->thisjob.encodeas,
            enc->current->thisjob.vallen,
            enc->current->thisjob.preamblen);
    */
}

int wandder_encode_preencoded_value(wandder_encode_job_t *job, void *valptr,
        uint32_t vallen) {

    uint8_t *buf;
    uint32_t rem, ret;

    save_value_to_encode(job, valptr, vallen);
    if (vallen == 0) {
        return 0;
    }

    job->encodedspace = (uint8_t *)malloc(job->preamblen + job->vallen);
    job->encodedlen = job->preamblen + job->vallen;

    buf = job->encodedspace;
    rem = job->encodedlen;

    if (job->identifier <= 30 && job->identclass != WANDDER_CLASS_UNKNOWN) {
        ret = encode_identifier_fast(job->identclass, job->identifier, buf);
    } else {
        ret = encode_identifier(job->identclass, job->identifier, buf, rem);
    }

    if (ret == 0) {
        return -1;
    }

    buf += ret;
    rem -= ret;

    ret = encode_length(job->vallen, buf, rem);

    if (ret == 0) {
        return -1;
    }

    buf += ret;
    rem -= ret;

    if (rem < job->vallen) {
        fprintf(stderr, "Encode error: not enough space for value\n");
        return -1;
    }
    memcpy(buf, job->valspace, job->vallen);
    return 0;
}

static inline int _wandder_encode_endseq(wandder_encoder_t *enc) {

    if (enc->current->parent == NULL) {
        return -1;
    }


    enc->current = enc->current->parent;
    enc->current->thisjob.preamblen = calc_preamblen(
            enc->current->thisjob.identifier, enc->current->childrensize);

    if (enc->current->parent) {
        enc->current->parent->childrensize +=
                enc->current->childrensize + enc->current->thisjob.preamblen;
    }

    return 0;
}

void wandder_encode_endseq(wandder_encoder_t *enc) {
    _wandder_encode_endseq(enc);
}

void wandder_encode_endseq_repeat(wandder_encoder_t *enc, int repeats) {
    int i;

    for (i = 0; i < repeats; i++) {
        if (_wandder_encode_endseq(enc) == -1) {
            break;
        }
    }
}

static inline uint32_t encode_pending(wandder_pend_t *p, uint8_t **buf,
        uint32_t *rem) {
    uint32_t ret;
    uint32_t tot = 0;
    if (p->thisjob.identifier <= 30 &&
            p->thisjob.identclass != WANDDER_CLASS_UNKNOWN) {
        ret = encode_identifier_fast(p->thisjob.identclass,
                p->thisjob.identifier, *buf);
    } else {
        ret = encode_identifier(p->thisjob.identclass,
                p->thisjob.identifier, *buf, *rem);
    }

    if (ret == 0) {
        return 0;
    }

    *buf += ret;
    *rem -= ret;
    tot += ret;

    if (p->childrensize != 0) {
        ret = encode_length(p->childrensize, *buf, *rem);
    } else {
        ret = encode_length(p->thisjob.vallen, *buf, *rem);
    }

    if (ret == 0) {
        return 0;
    }

    *buf += ret;
    *rem -= ret;
    tot += ret;
    if (p->thisjob.vallen > 0) {
        if (*rem < p->thisjob.vallen) {
            fprintf(stderr,
                    "Encode error: not enough space for value\n");
            assert(0);
            return 0;
        }
        if (p->thisjob.valspace) {
            memcpy(*buf, p->thisjob.valspace, p->thisjob.vallen);
        }

        *buf += p->thisjob.vallen;
        *rem -= p->thisjob.vallen;
        tot += p->thisjob.vallen;
    }

    return tot;
}

uint32_t encode_r(wandder_pend_t *p, uint8_t *buf, uint32_t rem) {
    uint32_t ret;
    uint32_t tot = 0;

    while (p) {

        if (p->thisjob.encodedlen > 0) {
            if (rem < p->thisjob.encodedlen) {
                fprintf(stderr,
                        "Encode error: not enough space for value\n");
                assert(0);
                return 0;
            }

            memcpy(buf, p->thisjob.encodedspace, p->thisjob.encodedlen);
            buf += p->thisjob.encodedlen;
            rem -= p->thisjob.encodedlen;
            tot += p->thisjob.encodedlen;

            assert(p->children == NULL);

        } else {
            if ((ret = encode_pending(p, &buf, &rem)) == 0) {
                break;
            }
            tot += ret;
        }

        if (p->children) {
            p = p->children;
            continue;
        }

        if (p->siblings) {
            p = p->siblings;
            continue;
        }

        p = p->parent;
        if (p == NULL) {
            break;
        }

        while (p && p->siblings == NULL) {
            p = p->parent;
        }
        if (p) {
            p = p->siblings;
        }
    }

    return tot;
}

void wandder_release_encoded_result(wandder_encoder_t *enc,
        wandder_encoded_result_t *res) {

    if (enc && pthread_mutex_trylock(&(enc->mutex)) == 0) {
        res->next = enc->freeresults;
        enc->freeresults = res;
        pthread_mutex_unlock(&(enc->mutex));
    } else if (res) {
        if (res->encoded) {
            free(res->encoded);
        }
        free(res);
    }

}

void wandder_release_encoded_results(wandder_encoder_t *enc,
        wandder_encoded_result_t *res, wandder_encoded_result_t *tail) {

    if (!enc) {
        while (res != NULL) {
            wandder_encoded_result_t *tmp = res;
            res = res->next;
            if (tmp->encoded) {
                free(tmp->encoded);
            }
            free(tmp);
        }
        return;
    }

    pthread_mutex_lock(&(enc->mutex));

    tail->next = enc->freeresults;
    enc->freeresults = res;

    pthread_mutex_unlock(&(enc->mutex));
}

wandder_encoded_result_t *wandder_encode_finish(wandder_encoder_t *enc) {

    wandder_encoded_result_t *result = NULL;

    if (enc->freeresults && pthread_mutex_trylock(&(enc->mutex)) == 0) {
        result = enc->freeresults;
        enc->freeresults = result->next;
        pthread_mutex_unlock(&(enc->mutex));
    } else {
        result = (wandder_encoded_result_t *)calloc(1,
                sizeof(wandder_encoded_result_t));
        result->encoded = NULL;
        result->len = 0;
        result->alloced = 0;
    }

    result->encoder = enc;
    result->next = NULL;
    result->len = enc->pendlist->childrensize + enc->pendlist->thisjob.preamblen;
    //printf("final size=%d %d %d\n", result->len, enc->pendlist->childrensize,
    //        enc->pendlist->thisjob.preamblen);
    if (result->alloced < result->len) {
        uint32_t x = 512;
        if (x < result->len) {
            x = result->len;
        }
        result->encoded = (uint8_t *)realloc(result->encoded, x);
        result->alloced = x;
    }

    if (encode_r(enc->pendlist, result->encoded, result->len) == 0) {
        fprintf(stderr, "Failed to encode wandder structure\n");
        wandder_release_encoded_result(enc, result);
        return NULL;
    }

    return result;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
