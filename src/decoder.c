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

#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#define _XOPEN_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>
#include <errno.h>

#include "src/itemhandler.h"
#include "src/libwandder.h"

#define DIGIT(x)  (x - '0')

#define TZ_TO_OFFSET(str) ( \
    ((DIGIT(*(str)) * 10 + DIGIT(*(str + 1))) * 3600) + \
    ((DIGIT(*(str + 2)) * 10 + DIGIT(*(str + 3))) * 60) )

struct wandder_dump_action WANDDER_NOACTION =
    (struct wandder_dump_action) {
        .name = "None",
        .descend = NULL,
        .interpretas = WANDDER_TAG_NULL
    };

static inline void free_item(wandder_item_t *item) {

    if (item->handler) {
        release_wandder_handled_item(item->handler, item->memsrc);
    } else {
        free(item);
    }
}

void free_cached_items(wandder_item_t *it, wandder_itemhandler_t *handler) {

    if (it == NULL) {
        return;
    }

    if (it->cachedchildren) {
        free_cached_items(it->cachedchildren, handler);
    }

    if (it->cachednext) {
        free_cached_items(it->cachednext, handler);
    }

    release_wandder_handled_item(handler, it->memsrc);
}

wandder_decoder_t *init_wandder_decoder(wandder_decoder_t *dec,
        uint8_t *source, uint32_t len, bool copy) {

    if (dec != NULL) {
        wandder_reset_decoder(dec);
        free_cached_items(dec->cacheditems, dec->item_handler);
        dec->cacheditems = NULL;
    } else {
        dec = (wandder_decoder_t *)malloc(sizeof(wandder_decoder_t));
        dec->toplevel = NULL;
        dec->current = NULL;
        dec->topptr = NULL;
        dec->nextitem = NULL;
        dec->item_handler = init_wandder_itemhandler(sizeof(wandder_item_t),
                10000);
        dec->foundlist_handler = init_wandder_itemhandler(
                sizeof(wandder_found_item_t) * 10, 10000);
        dec->found_handler = init_wandder_itemhandler(
                sizeof(wandder_found_t), 10000);

        dec->cacheditems = NULL;
        dec->cachedts = 0;
        memset(dec->prevgts, 0, 16);
    }

    if (copy) {
        dec->source = (uint8_t *)malloc(len);
        memcpy(dec->source, source, len);
        dec->ownsource = true;
    } else {
        dec->source = source;
        dec->ownsource = false;
    }
    dec->sourcelen = len;
    return dec;
}

void wandder_reset_decoder(wandder_decoder_t *dec) {

/*
    wandder_item_t *it = dec->current;

    while (it) {
        wandder_item_t *tmp = it;
        it = it->parent;
        free_item(tmp);
    }
*/

    dec->toplevel = NULL;
    dec->current = NULL;
    dec->topptr = NULL;
    dec->nextitem = NULL;
}

void free_wandder_decoder(wandder_decoder_t *dec) {

    free_cached_items(dec->cacheditems, dec->item_handler);

    if (dec->ownsource) {
        free(dec->source);
    }
    if (dec->item_handler) {
        destroy_wandder_itemhandler(dec->item_handler);
    }
    if (dec->found_handler) {
        destroy_wandder_itemhandler(dec->found_handler);
    }
    if (dec->foundlist_handler) {
        destroy_wandder_itemhandler(dec->foundlist_handler);
    }
    free(dec);

}

static inline wandder_item_t *create_new_item(wandder_decoder_t *dec) {

    wandder_item_t *item;
    wandder_itemblob_t *memsrc;
    if (dec->item_handler) {
        item = (wandder_item_t *)get_wandder_handled_item(dec->item_handler,
                &memsrc);
        item->memsrc = memsrc;
        item->handler = dec->item_handler;
    } else {
        item = (wandder_item_t *)malloc(sizeof(wandder_item_t));
        item->memsrc = NULL;
        item->handler = NULL;
    }

    item->parent = NULL;
    return item;
}

static int decode(wandder_decoder_t *dec, uint8_t *ptr, wandder_item_t *parent) {

    uint8_t tagbyte = *ptr;
    uint8_t shortlen;
    uint32_t prelen = 0;
    int i;
    wandder_item_t *item = NULL;
    uint8_t incache = 0;

    if (dec == NULL) {
        fprintf(stderr, "libwandder cannot decode using a NULL decoder.\n");
        return -1;
    }

    if (dec->current == NULL) {
        if (dec->cacheditems) {
            item = dec->cacheditems;
            incache = 1;
        } else {
            incache = 0;
        }
    } else if (dec->current == parent && parent->cachedchildren &&
            dec->current->descend == 1) {
        incache = 1;
        item = parent->cachedchildren;
    } else if (dec->current == parent && dec->current->descend == 0 &&
            dec->current->cachednext) {
        incache = 1;
        item = dec->current->cachednext;
    } else if (dec->current != parent && dec->current->cachednext) {
        incache = 1;
        item = dec->current->cachednext;
    } else {
        incache = 0;
    }

    if (incache) {
        dec->current = item;
        if (IS_CONSTRUCTED(dec->current)) {
            dec->current->descend = 1;
        } else {
            dec->current->descend = 0;
        }
        return 1;
    }

    while (parent != NULL && parent->indefform != 1 && ptr >= parent->valptr + parent->length ) {
        /* Reached end of preceding sequence */
        wandder_item_t *tmp = parent;
        parent = parent->parent;

        if (tmp == dec->toplevel) {
            dec->toplevel = NULL;
        }
        if (tmp == dec->current) {
            dec->current = NULL;
        }

        if (parent == NULL) {
            /* Reached end of the top level sequence */
            dec->current = NULL;
            return 0;
        }
    }

    item = create_new_item(dec);
    if (parent == NULL) {
        item->level = 0;
    } else {
        item->level = parent->level + 1;
    }

    item->parent = parent;

    /* First, let's try to figure out the tag type */

    if ((tagbyte & 0x1f) == 0x1f) {
        ptr ++;
        i = 0;
        prelen += 1;

        item->identifier = (*ptr) & 0x7f;
        while ((*ptr) & 0x80) {
            ptr ++;
            prelen += 1;
            item->identifier = (item->identifier << 7);
            item->identifier |= ((*ptr) & 0x7f);

            if (prelen >= 5) {
                fprintf(stderr, "libwandder does not support type fields longer than 4 bytes right now\n");
                if (item != dec->current) {
                    free_item(item);
                }
                return -1;
            }
        }
    } else {
        item->identifier = (tagbyte & 0x1f);
        prelen += 1;
        ptr ++;
    }
    item->identclass = ((tagbyte & 0xe0) >> 5);

    shortlen = *ptr;
    if ((shortlen & 0x80) == 0) {
        //definite short form
        item->indefform = 0;
        item->length = (shortlen & 0x7f);
        prelen += 1;
        ptr ++;
    } else {
        uint8_t lenoctets = (shortlen & 0x7f);
        if(lenoctets){
            //definite long form
            if (lenoctets > sizeof(item->length)) {
                fprintf(stderr, "libwandder does not support length fields longer than %zd bytes right now\n", sizeof(item->length));
                fprintf(stderr, "Tried to decode an item with a length field of %u bytes.\n", lenoctets);
                if (item != dec->current) {
                    free_item(item);
                }
                return -1;
            }
            ptr ++;
            item->length = 0;
            for (i = 0; i < (int)lenoctets; i++) {
                item->length = item->length << 8;
                item->length |= (*ptr);
                ptr ++;

            }
            prelen += (lenoctets + 1);
            item->indefform = 0;
        }
        else {
            //indfinite form
            item->length = 0;
            item->indefform = 1;
            prelen += 1;
            ptr ++;
        }
    }

    item->preamblelen = prelen;
    item->valptr = ptr;
    item->cachednext = NULL;
    item->cachedchildren = NULL;

    if (item->length == 0 && item->identclass == 0 && item->identifier == 0){
        //end of indef value

        if (item->parent == NULL) {
            /* Reached end of the top level sequence */
            dec->current = NULL;
            item->parent = NULL;
            return 0;
        }
        else{
            item->parent =  item->parent->parent;
        }
    }

    if (dec->current == parent && parent != NULL) {
        assert(parent->cachedchildren == NULL);
        parent->cachedchildren = item;
    } else if (dec->current) {
        assert(dec->current->cachednext == NULL);
        dec->current->cachednext = item;
    }

    dec->current = item;

    return 1;

}

static int first_decode(wandder_decoder_t *dec) {

    int ret;

    if (dec->cacheditems) {
        dec->current = dec->cacheditems;
    } else {
        ret = decode(dec, dec->source, NULL);
        if (ret <= 0) {
            return ret;
        }

        dec->cacheditems = dec->current;
    }

    dec->toplevel = dec->current;
    dec->topptr = dec->source;

    if (IS_CONSTRUCTED(dec->current)) {
        dec->current->descend = 1;
        dec->nextitem = dec->source + dec->current->preamblelen;
        ret = dec->current->preamblelen;
    } else {
        dec->nextitem = dec->source + dec->current->length +
                dec->current->preamblelen;
        ret = dec->current->length + dec->current->preamblelen;
    }

    return ret;
}

static inline int _decode_next(wandder_decoder_t *dec) {
    int ret;

    if (dec == NULL) {
        fprintf(stderr, "libwandder cannot decode using a NULL decoder.\n");
        return -1;
    }

    /* If toplevel is NULL, this is the first run */
    if (dec->toplevel == NULL) {
        return first_decode(dec);
    }

    if (dec->nextitem >= dec->source + dec->sourcelen){
        return 0; //reached end
    }

    /* if current is a constructed type, the next item is the first child 
     * of current */
    if ((IS_CONSTRUCTED(dec->current))) {
        ret = decode(dec, dec->nextitem, dec->current); 
    } else {
        /* if current is not a constructed type, use current's parent */
        ret = decode(dec, dec->nextitem, dec->current->parent);
    }

    if (ret <= 0) {
        return ret;
    }
    if (IS_CONSTRUCTED(dec->current)) {
        dec->current->descend = 1;
        dec->nextitem = dec->nextitem + dec->current->preamblelen;
        return dec->current->preamblelen;
    } else {
        dec->current->descend = 0;
    }

    dec->nextitem = dec->nextitem + dec->current->length +
            dec->current->preamblelen;

    return dec->current->length + dec->current->preamblelen;
}

int wandder_decode_next(wandder_decoder_t *dec) {
    return _decode_next(dec);
}

int wandder_decode_sequence_until(wandder_decoder_t *dec, uint32_t ident) {

    uint32_t thisident = 0;
    uint16_t baselevel = dec->current->level;
    wandder_item_t *orig = dec->current;
    uint8_t *savednext = dec->nextitem;

    do {
        if (_decode_next(dec) < 0) {
            return -1;
        }

        if (dec->current->level <= baselevel) {
            return 0;
        }

        thisident = dec->current->identifier;

        if (IS_CONSTRUCTED(dec->current) && thisident != ident) {
            wandder_decode_skip(dec);
            continue;
        }

    } while (thisident < ident);

    if (thisident == ident) {
        return 1;
    }

    dec->current = orig;
    dec->nextitem = savednext;
    return 0;
}

int wandder_decode_skip(wandder_decoder_t *dec) {

    if (dec == NULL) {
        fprintf(stderr, "libwandder cannot decode using a NULL decoder.\n");
        return -1;
    }

    /* If toplevel is NULL, this is the first run */
    if (dec->toplevel == NULL) {
        fprintf(stderr, "cannot call wandder_decode_skip() without at least one call to wandder_decode_next()");
        return -1;
    }

    int skipped = 0;

    if (dec->current->indefform){
        dec->nextitem = dec->current->valptr;
        while(*dec->nextitem != 0 || *(dec->nextitem+1) !=0 ){
            skipped += _decode_next(dec);

            if (dec->current->indefform){
                skipped += wandder_decode_skip(dec); 
                //not certian if recursive soloution should be used
                //but it works
            }
        }
        skipped += _decode_next(dec); //dec->nextitem+=2;

    }else {
        dec->current->descend = 0;
        dec->nextitem = dec->current->valptr + dec->current->length;
    }
    return dec->current->length + skipped;
}

const char *wandder_get_tag_string(wandder_decoder_t *dec) {

	uint8_t class;
	uint32_t ident;
    static char tmp[2048];

    if (dec == NULL) {
        fprintf(stderr, "libwandder cannot decode using a NULL decoder.\n");
        return "NULL decoder";
    }

	if (dec->current == NULL) {
		return "No current tag";
	}

	class = wandder_get_class(dec);
	ident = wandder_get_identifier(dec);

    if (class == WANDDER_CLASS_UNIVERSAL_PRIMITIVE) {
        switch (ident) {
            case WANDDER_TAG_BOOLEAN:
                return "Boolean";
            case WANDDER_TAG_INTEGER:
                return "Integer";
            case WANDDER_TAG_OCTETSTRING:
                return "Octet String";
            case WANDDER_TAG_OID:
                return "OID";
            case WANDDER_TAG_PRINTABLE:
                return "Printable String";
            case WANDDER_TAG_GENERALTIME:
                return "Generalized Time";
            case WANDDER_TAG_BITSTRING:
                return "Bit String";
            case WANDDER_TAG_RELATIVEOID:
                return "Relative OID";
            case WANDDER_TAG_UTF8STR:
                return "UTF8 String";
            case WANDDER_TAG_NULL:
                return "NULL";
            case WANDDER_TAG_OBJDESC:
                return "Object Description";
			case WANDDER_TAG_REAL:
				return "Real";
		    case WANDDER_TAG_ENUM:
                return "Enumerated Type";
            case WANDDER_TAG_NUMERIC:
                return "Numeric String";
            case WANDDER_TAG_IA5:
                return "IA5 String";
            case WANDDER_TAG_UTCTIME:
                return "UTC Time";
        }
    } else if (class == WANDDER_CLASS_UNIVERSAL_CONSTRUCT) {
        switch(ident) {
            case WANDDER_TAG_SEQUENCE:
                return "Sequence";
            case WANDDER_TAG_SET:
                return "Set";
        }
    } else if (class == WANDDER_CLASS_CONTEXT_PRIMITIVE) {
        snprintf(tmp, 2048, "[%u] (primitive)", ident);
        return (const char *)tmp;
    } else if (class == WANDDER_CLASS_CONTEXT_CONSTRUCT) {
        snprintf(tmp, 2048, "[%u] (construct)", ident);
        return (const char *)tmp;
    }

    return "Unknown Type";
}



uint8_t wandder_get_class(wandder_decoder_t *dec) {

    if (dec == NULL) {
        fprintf(stderr, "libwandder cannot decode using a NULL decoder.\n");
        return WANDDER_CLASS_UNKNOWN;
    }

    if (!dec->current) {
        return WANDDER_CLASS_UNKNOWN;
    }

    return dec->current->identclass;
}

uint32_t wandder_get_identifier(wandder_decoder_t *dec) {

    if (dec == NULL) {
        fprintf(stderr, "libwandder cannot decode using a NULL decoder.\n");
        return 0xffffffff;
    }

    if (dec->current) {
        return dec->current->identifier;
    }
    return 0xffffffff;
}

uint16_t wandder_get_level(wandder_decoder_t *dec) {
    if (dec == NULL) {
        fprintf(stderr, "libwandder cannot decode using a NULL decoder.\n");
        return 0xffff;
    }

    if (dec->current) {
        return dec->current->level;
    }
    return 0xffff;
}

uint32_t wandder_get_itemlen(wandder_decoder_t *dec) {

    if (dec == NULL) {
        fprintf(stderr, "libwandder cannot decode using a NULL decoder.\n");
        return 0;
    }

    if (dec->current) {
        if (dec->current->indefform){
            return 0;
        }
        return dec->current->length;
    }
    return 0;
}

uint8_t *wandder_get_itemptr(wandder_decoder_t *dec) {
    if (dec == NULL) {
        fprintf(stderr, "libwandder cannot decode using a NULL decoder.\n");
        return NULL;
    }

    if (dec->current) {
        return dec->current->valptr;
    }
    return NULL;
}


uint16_t stringify_octet_string(uint8_t *start, uint32_t length, char *space,
        uint16_t spacerem) {

    size_t n = length;

    if (n > spacerem - 1) {
        n = spacerem - 1;
    }

    strncpy(space, (char *)start, n);
    space[n] = '\0';
    return n+1;

}

static inline int64_t decode_integer(uint8_t *start, uint32_t *length) {
    uint64_t intval = 0;
    uint32_t i = 0;
    int isneg = 0;

    if (*start & 0x80) {
        /* MSB is set, so this should be treated as a negative number */
        isneg = 1;
    }

    for (i = 0; i < *length; i++) {
        if ( i == 8 ) {
            fprintf(stderr, "integer is too long for libwandder\n");
            *length = 0;
            return 0;
        }
        /* The uint64_t cast here is VERY important, otherwise the
         * right side of this expression ends up having a signed type.
         * That can lead to intval becoming a negative number just because
         * the MSB of the byte at length=0 happened to be set.
         * Instead, I use this cast to try and keep everything as unsigned
         * for as long as possible.
         */
        intval |= ((uint64_t)(*(start + i))) << (8 * (*length - 1 - i));
    }
    *length = i;

    if (isneg) {
        /* We're going to return a 64 bit signed int, so we need to
         * make sure that the extra bits beyond those that we just
         * decoded are properly set to 1 (as per 2's complement rules).
         *
         * Example: if we just received a 1 byte integer (-44), our
         * intval currently looks like 0x00000000000000d4. If we
         * just return that, the result is going to be interpreted as an
         * int64_t with the value of 212.
         * To get the "right" answer, we have to flip all of the bits in
         * the 7 other bytes that we didn't receive to get 0xffffffffffffffd4.
         * Callers will then see that number as -44.
         */

        uint64_t mask = ~((uint64_t)(pow(2ULL, (*length * 8)) - 1));
        intval |= mask;

    }
    return (int64_t)intval;
}


static uint32_t stringify_integer(uint8_t *start, uint32_t length, char *space,
        uint16_t spacerem) {

    int64_t intval = decode_integer(start, &length);
    snprintf(space, spacerem - 1, "%ld", intval);
    return length;
}

int64_t wandder_get_integer_value(wandder_item_t *c, uint32_t *intlen) {

    int64_t intval = 0;
    uint32_t len = c->length;

    intval = decode_integer(c->valptr, &len);
    if (intlen) {
        *intlen = len;
    }

    return intval;
}

static inline uint16_t oid_to_string(uint8_t *start, uint32_t length,
        char *space, uint16_t spacerem, uint16_t used) {

    int currlen;
    char tmp[1024];
    uint32_t nextval = 0;

    currlen = 1;
    while (length > 0 && used < spacerem) {
        nextval = nextval << 8;
        nextval |= ((*start & 0x7f));

        if ((*start) & 0x80) {
            currlen ++;
            start ++;
            length -= 1;
            continue;
        }

        start ++;
        length -= 1;
        if (currlen > 4) {
            fprintf(stderr, "OID content is too long for libwandder\n");
            return 0;
        }

        snprintf(tmp, 1024, ".%u", nextval);
        strncat(space, tmp, spacerem - used);

        used += strlen(tmp);
        currlen = 1;
        nextval = 0;
    }
    return used;
}

uint32_t stringify_oid(uint8_t *start, uint32_t length, char *space,
        uint16_t spacerem) {

    uint8_t firstoct = *start;
    int ret;

    ret = snprintf(space, spacerem, "%u.%u", firstoct / 40, firstoct % 40);

    if (ret < 0) {
        return 0;
    }

    start ++;
    length -= 1;
    return oid_to_string(start, length, space, spacerem, ret);

}

uint32_t stringify_roid(uint8_t *start, uint32_t length, char *space,
        uint16_t spacerem) {

    if (spacerem == 0) {
        return 0;
    }
    space[0] = '\0';
    return oid_to_string(start, length, space, spacerem, 0);
}

struct timeval wandder_generalizedts_to_timeval(wandder_decoder_t *dec,
        char *gts, int len) {
    struct timeval tv;
    struct tm tm, localres;
    char *nxt = NULL;
    char *skipto = NULL;
    uint32_t ms = 0;
    int tzcorrect = 0, gmtoffset = 0;
    time_t current;

    tv.tv_sec = 0;
    tv.tv_usec = 0;

    if (len < 14) {
        fprintf(stderr, "Generalized time string %s is too short!\n", gts);
        return tv;
    }

    nxt = gts + 14;     /* YYYYmmddHHMMSS */

    if (*nxt == '.') {
        skipto = nxt + 1;

        while (*skipto) {
            if (*skipto == 'Z' || *skipto == '+' || *skipto == '-') {
                break;
            }

            if (*skipto < '0' || *skipto > '9') {
                fprintf(stderr, "Unexpected character in generalized time string %s (%c)\n", gts, *skipto);
                return tv;
            }
            ms = ms * 10 + ((*skipto) - '0');
            skipto ++;
        }
    }

    if (memcmp(gts, dec->prevgts, 14) == 0) {
        tv.tv_sec = dec->cachedts;
        tv.tv_usec = ms * 1000;
        return tv;
    }

    if (strptime(gts, "%Y%m%d%H%M%S", &tm) == NULL) {
        fprintf(stderr, "strptime failed to parse generalized time: %s\n", gts);
        return tv;
    }
    /* The time is going to be interpreted as UTC, so we'll need to
     * remove any timezone differences using TZ_TO_OFFSET. However, mktime
     * assumes local time so we'll need to also add the time difference
     * between us and UTC to get a sensible unix timestamp.
     *
     * TODO maybe only do the localtime() call if the TZ is different
     * to previously?
     */
    current = time(NULL);
    gmtoffset = (localtime_r(&current, &localres))->tm_gmtoff;

    switch(*skipto) {
        case 'Z':
            tzcorrect = gmtoffset;
            break;
        case '+':
            tzcorrect = gmtoffset - TZ_TO_OFFSET(skipto + 1);
            break;
        case '-':
            tzcorrect = gmtoffset + TZ_TO_OFFSET(skipto + 1);
            break;
    }

    tm.tm_isdst = -1;       // important! required to do DST calc automatically
    tm.tm_gmtoff = 0;
    tv.tv_sec = mktime(&tm) + tzcorrect;
    tv.tv_usec = ms * 1000;

    dec->cachedts = tv.tv_sec;
    memcpy(dec->prevgts, gts, 14);
    dec->prevgts[14] = '\0';
    return tv;
}

uint32_t stringify_gentime(uint8_t *start, uint32_t length, char *space,
        uint16_t spacerem) {

    /* TODO maybe parse this and print it a bit nicer? */
    return stringify_octet_string(start, length, space, spacerem);
}

char * wandder_get_valuestr(wandder_item_t *c, char *space, uint16_t len,
        uint8_t interpretas) {

    uint8_t datatype;
    char staticspace[2048];

    if (c == NULL) {
        return NULL;
    }

    if (space == NULL) {
        space = staticspace;
        len = 2048;
    }

    if (c->identclass == WANDDER_CLASS_UNIVERSAL_PRIMITIVE ||
            c->identclass == WANDDER_CLASS_UNIVERSAL_CONSTRUCT) {
        if (c->identifier <= 31) {
            datatype = c->identifier;
        } else {
            fprintf(stderr, "Unexpected identifier for supposedly universal tag: %u\n", c->identifier);
            return NULL;
        }
    } else {
        if (interpretas > 31) {
            fprintf(stderr, "'Interpret as' tags must be between 0-31 inclusive (not %u)\n", interpretas);
            return NULL;
        }

        datatype = interpretas;
    }

    switch (datatype) {
        case WANDDER_TAG_SEQUENCE:
        case WANDDER_TAG_SET:
        case WANDDER_TAG_NULL:
            space[0] = '\0';
            break;
        case WANDDER_TAG_OCTETSTRING:
        case WANDDER_TAG_PRINTABLE:
        case WANDDER_TAG_UTF8STR:
        case WANDDER_TAG_IA5:
            stringify_octet_string(c->valptr, c->length, space, len);
            break;

        case WANDDER_TAG_INTEGER:
        case WANDDER_TAG_ENUM:
            if (stringify_integer(c->valptr, c->length, space, len) == 0) {
                return NULL;
            }
            break;

        case WANDDER_TAG_OID:
            if (stringify_oid(c->valptr, c->length, space, len) == 0) {
                return NULL;
            }
            break;

        case WANDDER_TAG_GENERALTIME:
            if (stringify_gentime(c->valptr, c->length, space, len) == 0) {
                return NULL;
            }
            break;

        case WANDDER_TAG_RELATIVEOID:
            if (stringify_roid(c->valptr, c->length, space, len) == 0) {
                return NULL;
            }
            break;

        case WANDDER_TAG_BOOLEAN:
        case WANDDER_TAG_BITSTRING:
        case WANDDER_TAG_OBJDESC:
        case WANDDER_TAG_REAL:
        case WANDDER_TAG_NUMERIC:
        case WANDDER_TAG_UTCTIME:
        default:
            fprintf(stderr, "No stringify support for type %u just yet...\n",
                    datatype);
            return NULL;
    }

    return space;
}

static wandder_found_t *add_found_item(wandder_item_t *item,
        wandder_found_t *found, int targetid, uint16_t type,
        wandder_decoder_t *dec) {

    wandder_itemblob_t *fsrc;

    if (found == NULL) {
        found = (wandder_found_t *)get_wandder_handled_item(dec->found_handler,
                &fsrc);

        found->handler = dec->found_handler;
        found->memsrc = fsrc;

        found->list = (wandder_found_item_t *)get_wandder_handled_item(
                dec->foundlist_handler, &fsrc);
        found->list_handler = dec->foundlist_handler;
        found->list_memsrc = fsrc;
        found->itemcount = 0;
        found->alloced = 10;
    }

    if (found->itemcount == found->alloced) {
        found->list = (wandder_found_item_t *)realloc(found->list,
                sizeof(wandder_found_item_t) * (found->alloced + 10));
        if (found->list_handler) {
            release_wandder_handled_item(found->list_handler,
                    found->list_memsrc);
            found->list_handler = NULL;
            found->list_memsrc = NULL;
        }
        found->alloced += 10;
    }

    found->list[found->itemcount].item = (wandder_item_t *)
            get_wandder_handled_item(dec->item_handler, &fsrc);

    memcpy(found->list[found->itemcount].item, item, sizeof(wandder_item_t));
    found->list[found->itemcount].targetid = targetid;
    found->list[found->itemcount].interpretas = type;
    found->list[found->itemcount].item->memsrc = fsrc;
    found->list[found->itemcount].item->handler = dec->item_handler;
    found->itemcount ++;

    return found;

}

void wandder_free_found(wandder_found_t *found) {

    int i;

    if (found == NULL) {
        return;
    }

    for (i = 0; i < found->itemcount; i++) {
        free_item(found->list[i].item);
    }
    if (found->list_handler) {
        release_wandder_handled_item(found->list_handler, found->list_memsrc);
    } else {
        free(found->list);
    }

    if (found->handler) {
        release_wandder_handled_item(found->handler, found->memsrc);
    } else {
        free(found);
    }
}

static inline void check_if_found_ctxt(wandder_decoder_t *dec, uint32_t ident,
        wandder_target_t *targets, int targetcount, wandder_found_t **found,
        wandder_dumper_t *actions) {

    int i;

    for (i = 0; i < targetcount; i++) {
        if (targets[i].found) {
            continue;
        }

        if (ident != targets[i].itemid) {
            continue;
        }

        if (actions != targets[i].parent) {
            continue;
        }

        *found = add_found_item(dec->current, *found, i,
                actions->members[i].interpretas, dec);
        targets[i].found = true;
    }
}

static inline void check_if_found_noctxt(wandder_decoder_t *dec, uint32_t ident,
        wandder_target_t *targets, int targetcount, wandder_found_t **found,
        wandder_dumper_t *actions, uint16_t interpretas) {

    int i;

    for (i = 0; i < targetcount; i++) {
        if (targets[i].found) {
            continue;
        }

        if (ident != targets[i].itemid) {
            continue;
        }

        if (actions != targets[i].parent) {
            continue;
        }

        *found = add_found_item(dec->current, *found, i, interpretas, dec);
        targets[i].found = true;
    }
}

int wandder_search_items(wandder_decoder_t *dec, uint16_t level,
        wandder_dumper_t *actions, wandder_target_t *targets,
        int targetcount, wandder_found_t **found, int stopthresh) {


    struct wandder_dump_action *act;
    int ret, i;
    uint32_t ident;
    int atthislevel = 0;

    ret = 0;

    if (*found && (*found)->itemcount == stopthresh) {
        return stopthresh;
    }

    if (level == 0) {
        for (i = 0; i < targetcount; i++) {
            targets[i].found = false;
        }
        if (stopthresh == 0) {
            stopthresh = targetcount;
        }

    }

    ret = wandder_decode_next(dec);
    if (ret <= 0) {
        return ret;
    }

    while (1) {

        if (*found && (*found)->itemcount == stopthresh) {
            break;
        }

        if (wandder_get_level(dec) < level) {
            break;
        }

        ident = wandder_get_identifier(dec);
        if (wandder_get_class(dec) == WANDDER_CLASS_CONTEXT_PRIMITIVE) {
            check_if_found_ctxt(dec, ident, targets, targetcount, found,
                    actions);
        }

        if (wandder_get_class(dec) == WANDDER_CLASS_CONTEXT_CONSTRUCT) {
            check_if_found_ctxt(dec, ident, targets, targetcount, found,
                    actions);

            act = &(actions->members[ident]);
            if (act == NULL || act->descend == NULL) {
                return 0;
            }
            assert(act->descend != NULL);
            ret = wandder_search_items(dec, level + 1, act->descend, targets,
                    targetcount, found, stopthresh);
            if (ret <= 0) {
                break;
            }
            continue;
        }

        if (wandder_get_class(dec) == WANDDER_CLASS_UNIVERSAL_PRIMITIVE) {

            check_if_found_noctxt(dec, atthislevel, targets, targetcount, found,
                    actions, ident);
        }

        if (wandder_get_class(dec) == WANDDER_CLASS_UNIVERSAL_CONSTRUCT) {
            check_if_found_noctxt(dec, atthislevel, targets, targetcount, found,
                    actions, ident);
            ret = wandder_search_items(dec, level + 1,
                    actions->sequence.descend, targets,
                    targetcount, found, stopthresh);

            if (ret <= 0) {
                break;
            }
            continue;
        }

        atthislevel ++;
        ret = wandder_decode_next(dec);
        if (ret <= 0) {
            break;
        }
    }

    if (level > 0) {
        if (ret <= 0) {
            return ret;
        }
        return 1;
    }

    if (ret < 0) {
        return ret;
    }

    if (*found != NULL) {
        return (*found)->itemcount;
    }
    return 0;
}


int wandder_decode_dump(wandder_decoder_t *dec, uint16_t level,
        wandder_dumper_t *actions, char *name) {

    char space[2048];
    int ret;
    uint32_t ident;
    struct wandder_dump_action *act;

    if (dec == NULL) {
        fprintf(stderr, "libwandder cannot decode using a NULL decoder.\n");
        return -1;
    }

    /*
    if (level != 0) {
        printf("[%u] %u %s %u\n", wandder_get_identifier(dec),
                wandder_get_level(dec), name, wandder_get_itemlen(dec));
    }
    */

    ret = wandder_decode_next(dec);
    if (ret <= 0) {
        return ret;
    }
    while (1) {

        if (wandder_get_level(dec) < level) {
            break;
        }

        ident = wandder_get_identifier(dec);
        act = &(actions->members[ident]);
        if (wandder_get_class(dec) == WANDDER_CLASS_CONTEXT_PRIMITIVE) {

            assert(act->descend == NULL);
            if (!wandder_get_valuestr(dec->current, space, 2048, act->interpretas)) {
                return -1;
            }

            printf("[%u] %u %s %s\n", ident, level, act->name, space);
        }

        if (wandder_get_class(dec) == WANDDER_CLASS_CONTEXT_CONSTRUCT) {
            printf("[%u] %u %s --\n", ident, level, act->name);

            assert(act->descend != NULL);
            ret = wandder_decode_dump(dec, level + 1, act->descend, act->name);
            if (ret <= 0) {
                return ret;
            }
            continue;
        }

        if (wandder_get_class(dec) == WANDDER_CLASS_UNIVERSAL_PRIMITIVE) {
            if (!wandder_get_valuestr(dec->current, space, 2048, WANDDER_TAG_NULL)) {
                return -1;
            }

            printf("[%u] %u %s %s\n", ident, level, act->name, space);
        }

        if (wandder_get_class(dec) == WANDDER_CLASS_UNIVERSAL_CONSTRUCT) {
            printf("%u %s --\n", level, actions->sequence.name);
            ret = wandder_decode_dump(dec, level + 1,
                    actions->sequence.descend, actions->sequence.name);

            if (ret <= 0) {
                return ret;
            }
            continue;
        }

        ret = wandder_decode_next(dec);
        if (ret <= 0) {
            return ret;
        }
    }

    return 1;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
