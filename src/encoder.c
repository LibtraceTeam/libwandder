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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>
#include "wandder_internal.h"
#include "src/libwandder.h"

#define MAXLENGTHOCTS 8

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
            //I think this line is a bug and should part of the identifier size 
            //(bit 8 is reserved for the stop bit of the long id form)
            //where as in the long form of the length, the number of octets is specfied
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
    int i;

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
    uint16_t lenocts;
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

static inline int encode_time_inline(
        uint32_t len, struct timeval *tv, char* returnbuf, int time_format) {
    
    struct tm tm;
    time_t tstamp;
    char timebuf[768];

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

    switch (time_format) {
        case WANDDER_G_TIME: 
            strftime(timebuf, 768, "%y%m%d%H%M%S", &tm);
            break;
        default:
            fprintf(stderr, 
                "Encode error: unexpected format for timeval, using UTC\n");
        case WANDDER_UTC_TIME:
            strftime(timebuf, 768, "%y%m%d%H%M%S", &tm);
            break;
    }
    snprintf(returnbuf, 1024, "%s.%03" PRId64 "Z", timebuf,
            (int64_t)(tv->tv_usec / 1000));

    return strlen(returnbuf);
}

static uint32_t encode_time(wandder_encode_job_t *p, void *valptr,
        uint32_t len, int time_format) {

    struct timeval *tv = (struct timeval *)valptr;
    char timebuf[1024];

    int towrite = encode_time_inline(len, tv, timebuf, time_format);
    if (towrite == 0)
        return  0;

    VALALLOC(towrite, p);
    p->vallen = towrite;

    memcpy(p->valspace, timebuf, towrite);
    return (uint32_t)towrite;
}

static uint32_t encode_time_ber(void *valptr,
        uint32_t len, uint8_t *buf, uint32_t rem, int time_format) {

    struct timeval *tv = (struct timeval *)valptr;
    size_t ret;
    char timebuf[1024];

    int towrite = encode_time_inline(len, tv, timebuf, time_format);
    if (towrite == 0)
        return  0;

    ret = encode_length(towrite, buf, rem);
    buf += ret;
    rem -= ret;

    memcpy(buf, timebuf, towrite);
    buf += towrite;
    rem -= towrite;

    return towrite + ret;
}



static inline void save_value_to_encode(wandder_encode_job_t *job, void *valptr,
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

        case WANDDER_TAG_UTCTIME:
            if (encode_time(job, valptr, vallen, WANDDER_UTC_TIME) == 0) {
                return;
            }
            job->preamblen = calc_preamblen(job->identifier, vallen);
            break;

        case WANDDER_TAG_GENERALTIME:
            /* Timeval to general TS */
            if (encode_time(job, valptr, vallen, WANDDER_G_TIME) == 0) {
                return;
            }
            job->preamblen = calc_preamblen(job->identifier, vallen);
            break;
        case WANDDER_TAG_INTEGER:
        case WANDDER_TAG_ENUM:
            /* Signed int to Integer */
            if (encode_integer(job, valptr, vallen) == 0) {
                return;
            }
            job->preamblen = calc_preamblen(job->identifier, vallen);
            break;

        case WANDDER_TAG_OID:
            /* Byte array to OID */
            if (encode_oid(job, valptr, vallen) == 0) {
                return;
            }
            job->preamblen = calc_preamblen(job->identifier, vallen);
            break;


        case WANDDER_TAG_NULL:
            job->vallen = 0;
            job->preamblen = calc_preamblen(job->identifier, vallen);
            break;

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
            return;
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
        if (enc->current->parent) {
            enc->current->parent->lastchild = next;
        }
        enc->current = next;
    }

    enc->current->thisjob.identclass = itemclass;
    enc->current->thisjob.identifier = idnum;
    enc->current->thisjob.encodeas = encodeas;
    save_value_to_encode(&(enc->current->thisjob), valptr, vallen);
    if (enc->current->parent) {
        enc->current->parent->childrensize +=
            (enc->current->thisjob.vallen +
             enc->current->thisjob.preamblen);
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

static inline int job_requires_valcopy(wandder_encode_job_t *job) {
    if (job->vallen == 0) {
        return 0;
    }

    switch(job->encodeas) {
        case WANDDER_TAG_IPPACKET:
        case WANDDER_TAG_NULL:
        case WANDDER_TAG_SEQUENCE:
        case WANDDER_TAG_SET:
            return 0;
    }

    return 1;
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
        if (job_requires_valcopy(&(p->thisjob))) {
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

static inline size_t encode_length_indefinite(uint8_t *buf, ptrdiff_t rem) {
    if (rem <= 0) {
        fprintf(stderr, "Encode error: no more space while encoding length\n");
        return 0;
    }
    *buf = 0x80; //TODO should I set a #define for this somewhere or just use "magic" value?
    return 1;
}

inline size_t calculate_length(uint8_t idnum, uint8_t class, 
        uint8_t encodeas, size_t vallen) {
    size_t idlen = 0;
    size_t lenlen = 0;
    size_t loglen = 0;
    size_t totallen = 0;

    if (idnum <= 30) { //idlen 
        idlen += 1;
    } else {
        loglen = WANDDER_LOG128_SIZE(idnum);
        idlen += (1 + loglen);
    }

    switch (encodeas) {
        case WANDDER_TAG_INTEGER:
        case WANDDER_TAG_ENUM:{
                totallen = idlen + MAXLENGTHOCTS + 2; //integers are weird
            }
            break;

        case WANDDER_TAG_OID:{
                totallen = idlen + vallen; //( +1 -1 ) 
                // first two bytes of OID are combined so -1
                // also includ len field so +1 

            }
            break;
        
        default:
            if (vallen < 128) {
                lenlen = 1;
            } else {
                loglen = WANDDER_LOG256_SIZE(vallen);
                if (vallen > WANDDER_EXTRA_OCTET_THRESH(loglen)) {
                    loglen++;
                }
                lenlen = loglen +1;
            }



            totallen = idlen + lenlen + vallen;
        break;
    }

    return totallen;
}

inline size_t encode_here_ber(uint8_t idnum, uint8_t class, uint8_t encodeas, 
        uint8_t* valptr, size_t vallen, uint8_t* ptr, ptrdiff_t rem){
    
    size_t ret = 0;
    uint8_t* init_ptr = ptr;
    
    switch(encodeas) {
        case WANDDER_TAG_OCTETSTRING:
        case WANDDER_TAG_UTF8STR:
        case WANDDER_TAG_NUMERIC:
        case WANDDER_TAG_PRINTABLE:
        case WANDDER_TAG_IA5:
        case WANDDER_TAG_RELATIVEOID:

            ret = encode_identifier(class, idnum, ptr, rem);
            ptr += ret;
            rem -= ret;
            
            if(class & 1){ //if type is constructed use indefinite length 
                ret = encode_length_indefinite(ptr, rem);
            }
            else {
                ret = encode_length(vallen, ptr, rem);
            }
            ptr += ret;
            rem -= ret;

            memcpy(ptr, valptr, vallen);
            ptr += vallen;
            rem -= vallen;
            break;

        case WANDDER_TAG_INTEGER:
        case WANDDER_TAG_ENUM:

            ret = ber_rebuild_integer(class, idnum, valptr, vallen, ptr);
            ptr += ret;
            rem -= ret;
            break;

        case WANDDER_TAG_OID:

            ret = encode_identifier(class, idnum, ptr, rem);
            ptr += ret;
            rem -= ret;
            
            if(class & 1){
                ret = encode_length_indefinite(ptr, rem);
            }
            else {
                ret = encode_length(vallen-1, ptr, rem);
            }
            ptr += ret;
            rem -= ret;

            if (vallen < 2) {
                fprintf(stderr, "Encode error: OID is too short!\n");
                return 0;
            }
            if ((vallen - 2) > rem) { 
                fprintf(stderr, "Encode error: Not enough space for OID!\n");
                return 0;
            }

            *ptr = (40 * valptr[0]) + valptr[1]; //not sure why this is a thing
            ptr += 1;
            rem -=1;

            size_t templen = vallen - 2;

            memcpy(ptr, valptr + 2, templen);

            ptr += templen;
            rem -= templen;

            break;


        case WANDDER_TAG_NULL:
                ret = encode_identifier(class, idnum, ptr, rem);
                ptr += ret;
                rem -= ret;
                
                if(class & 1){
                    ret = encode_length_indefinite(ptr, rem);
                }
                else {
                    ret = encode_length(vallen, ptr, rem);
                }
                ptr += ret;
                rem -= ret;
            break;

        case WANDDER_TAG_SEQUENCE:
        case WANDDER_TAG_SET:
                ret = encode_identifier(class, idnum, ptr, rem);
                ptr += ret;
                rem -= ret;
                
                if(class & 1){
                    ret = encode_length_indefinite(ptr, rem);
                }
                else {
                    ret = encode_length(vallen, ptr, rem);
                }
                ptr += ret;
                rem -= ret;
            break;
        case WANDDER_TAG_IPPACKET:
                ret = encode_identifier(class, idnum, ptr, rem);
                ptr += ret;
                rem -= ret;
                
                ret = encode_length(vallen, ptr, rem);
                ptr += ret;
                rem -= ret;

                //memset(ptr, 0, vallen); //should this bea memcpy? 
                memcpy(ptr, valptr, vallen);
                ptr+=vallen;
                rem-=vallen;

            break;
        case WANDDER_TAG_GENERALTIME:
            ret = encode_identifier(class, idnum, ptr, rem);
            ptr += ret;
            rem -= ret;

             /* Timeval to general TS */
            ret = encode_time_ber(valptr, vallen, ptr, rem, WANDDER_G_TIME);
            ptr += ret;
            rem -= ret;
            if (ret == 0) {
                //TODO error or something?
            }

            break;

        case WANDDER_TAG_UTCTIME:
            ret = encode_identifier(class, idnum, ptr, rem);
            ptr += ret;
            rem -= ret;
            ret = encode_time_ber(valptr, vallen, ptr, rem, WANDDER_UTC_TIME);
            ptr += ret;
            rem -= ret;
            if (ret == 0) {
                //TODO error or something?
            }

            break;

        default:
            fprintf(stderr, "Encode error: unable to encode tag type %d\n",
                    encodeas);
            assert(0);
    }

    return ptr - init_ptr;
}

size_t wandder_encode_inplace_ber(
        uint8_t class, 
        uint8_t idnum, 
        uint8_t encodeas, 
        uint8_t * valptr,
        size_t vallen,
        void* buf, 
        ptrdiff_t rem){

    ptrdiff_t totallen = calculate_length(idnum, class, encodeas, vallen);

    if (totallen > rem){
        fprintf(stderr, "Encode error: not enough room\n");
        return 0;
    }

    size_t ret = 0;

    uint8_t * ptr = buf;

    ret = encode_here_ber(idnum, class, encodeas, valptr, vallen, ptr, rem);

    if(ret != totallen){
        printf("calc length:%4lu, real length:%4lu\n", totallen, ret);
        assert(0);
    }

    return ret;
}

wandder_buf_t * wandder_encode_new_ber(
        uint8_t class, 
        uint8_t idnum, 
        uint8_t encodeas, 
        uint8_t * valptr,
        size_t vallen){

    size_t totallen = calculate_length(idnum, class, encodeas, vallen);

    wandder_buf_t* itembuf = malloc(sizeof *itembuf);

    itembuf->buf = malloc(totallen);
    itembuf->len  = totallen;
    ptrdiff_t rem = totallen;  

    size_t ret = 0;

    uint8_t * ptr = itembuf->buf;

    ret = encode_here_ber(idnum, class, encodeas, valptr, vallen, ptr, rem);
    itembuf->len = ret;

    if(ret != totallen){
        printf("calc length:%4lu, real length:%4lu\n", totallen, ret);
        assert(0);
    }

    return itembuf;
}

//returns the number of bytes written (usually const unless an error)
size_t ber_rebuild_integer(
        uint8_t itemclass, 
        uint32_t idnum, 
        void *valptr, 
        size_t vallen,
        void* buf) {

    size_t rem = MAXLENGTHOCTS + 3;
    size_t lenocts = 0;
    int64_t val = 0;
    uint8_t *ptr = buf;
    ptrdiff_t i;

    if (vallen == 8) {
        val = *((int64_t *)valptr);
    } else if (vallen == 4) {
        val = *((int32_t *)valptr);
    } else if (vallen == 2) {
        val = *((int16_t *)valptr);
    } else if (vallen == 1) {
        val = *((int8_t *)valptr);
    } else {
        fprintf(stderr, "Encode error: unexpected length for integer type: %lu\n",
            vallen);
        return 0;
    }

    if (val < 0) {
        /* Play it safe with negative numbers (or seemingly negative ones) */
        lenocts = vallen;
    } else {
        lenocts = WANDDER_LOG256_SIZE(val);
        if (lenocts == 0) {
            lenocts = 1;
        }

        if (lenocts > 7) {
            lenocts = vallen;
        }
        if (lenocts < vallen && val >= WANDDER_EXTRA_OCTET_THRESH(lenocts)) { //TODO
            lenocts ++; //this is to ensure a positive number with the MSB set is not negitive
        }
    }

    size_t ret = encode_identifier(itemclass, idnum, ptr, rem);
    ptr += ret;
    rem -= ret;

    //lenocts = length of encoded value
    //lenlen  = length of length value 
    //total len = class|id(1) + lenhdr(1) + lenlen(1) + lenval(lenlen) + value(lenoctets)

    size_t lenlen = MAXLENGTHOCTS - lenocts + 1; //length of length field 

    *ptr = 0x80;
    *ptr |= lenlen;

    for (i = 0 ; i < lenlen; i++){
        ptr++;
        *ptr = 0;
    }
    *ptr = lenocts;

    for (i = lenocts - 1; i >= 0; i--) {
        ptr[i+1] = (val & 0xff);
        val = val >> 8;
    }
    return MAXLENGTHOCTS + 3;
}


static inline ptrdiff_t rem_grow_check(wandder_encoder_ber_t *enc_ber, size_t totallen){

    ptrdiff_t rem = enc_ber->alloc_len - enc_ber->len;
    if (totallen > rem){
        size_t new_alloc = enc_ber->len + totallen + enc_ber->increment;
        uint8_t *new_buf = realloc(enc_ber->buf, new_alloc);
                if (new_buf == NULL){
            //TODO, handle mem fail
            printf("realloc failed\n");
            assert(0);
        }
        enc_ber->alloc_len = new_alloc;
        if (new_buf != enc_ber->buf){
            ptrdiff_t offset = new_buf - enc_ber->buf;

            enc_ber->buf += offset;
            enc_ber->ptr += offset;
        }
        rem = enc_ber->alloc_len - enc_ber->len;
    }

    return rem;
}

wandder_encoder_ber_t* wandder_init_encoder_ber(size_t init_alloc, size_t increment){

    wandder_encoder_ber_t* enc_ber = calloc(1, sizeof *enc_ber);

    enc_ber->buf = malloc(init_alloc);
    enc_ber->ptr = enc_ber->buf;
    enc_ber->alloc_len = init_alloc;
    enc_ber->increment = increment;

    return enc_ber;
}

void wandder_encode_next_ber(wandder_encoder_ber_t *enc_ber, uint8_t encodeas,
        uint8_t itemclass, uint32_t idnum, void *valptr, uint32_t vallen){

    size_t totallen = calculate_length(idnum, itemclass, encodeas, vallen);
    size_t ret;
    ptrdiff_t rem;

    rem = rem_grow_check(enc_ber, totallen);
    if (rem > 0) {
        ret = encode_here_ber(idnum, itemclass, encodeas, valptr, vallen, enc_ber->ptr, rem);

        enc_ber->ptr += ret;
        enc_ber->len += ret;
    }
}

wandder_encoded_result_ber_t* wandder_encode_finish_ber(wandder_encoder_ber_t *enc_ber){

    wandder_encoded_result_ber_t* res = malloc(sizeof *res);
    res->buf = enc_ber->buf;
    res->len = enc_ber->len;
    enc_ber->buf = NULL;
    wandder_reset_encoder_ber(enc_ber);
    return res;

}

void wandder_encode_endseq_ber(wandder_encoder_ber_t *enc_ber, uint32_t depth){

    depth *=2; //an ENDSEQ is 2 bytes each

    ptrdiff_t rem = rem_grow_check(enc_ber, depth);

    if (rem > 0) {
        memset(enc_ber->ptr, 0, depth);

        enc_ber->ptr +=depth;
        enc_ber->len +=depth;
    }
}

void wandder_reset_encoder_ber(wandder_encoder_ber_t* enc_ber){

    if (!enc_ber->buf) {
        enc_ber->buf = malloc(enc_ber->alloc_len);
    }
    enc_ber->ptr = enc_ber->buf;
    enc_ber->len = 0;

}

void wandder_free_encoder_ber(wandder_encoder_ber_t* enc_ber){

    if(enc_ber){
        if(enc_ber->buf){
            free(enc_ber->buf);
        }
        free(enc_ber);
        return;
    }
}

void wandder_free_encoded_result_ber(wandder_encoded_result_ber_t* res_ber){

    if(res_ber){
        if(res_ber->buf){
            free(res_ber->buf);
        }
        free(res_ber);
        return;
    }
}

void wandder_append_preencoded_ber(wandder_encoder_ber_t* enc_ber, wandder_buf_t* item_buf){

    ptrdiff_t rem = rem_grow_check(enc_ber, item_buf->len);

    if (rem > 0) {
        memcpy(enc_ber->ptr, item_buf->buf, item_buf->len);
        enc_ber->ptr += item_buf->len;
        enc_ber->len += item_buf->len;
    }

}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
