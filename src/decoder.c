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

void init_wandder_decoder(wandder_decoder_t *dec, uint8_t *source, uint32_t len,
        bool copy) {

    dec->toplevel = NULL;
    dec->current = NULL;
    dec->topptr = NULL;
    dec->nextitem = NULL;

    if (copy) {
        dec->source = (char *)malloc(len);
        memcpy(dec->source, source, len);
        dec->ownsource = true;
    } else {
        dec->source = source;
        dec->ownsource = false;
    }
    dec->sourcelen = len;
}

void wandder_reset_decoder(wandder_decoder_t *dec) {
    if (dec->toplevel && dec->toplevel != dec->current) {
        free(dec->toplevel);
    }

    if (dec->current) {
        free(dec->current);
    }

    dec->toplevel = NULL;
    dec->current = NULL;
    dec->topptr = NULL;
    dec->nextitem = NULL;
}


void free_wandder_decoder(wandder_decoder_t *dec) {

    if (dec->ownsource) {
        free(dec->source);
    }

    if (dec->toplevel && dec->toplevel != dec->current) {
        free(dec->toplevel);
    }

    if (dec->current) {
        free(dec->current);
    }
}

static inline wandder_item_t *create_new_item(wandder_decoder_t *dec) {

    wandder_item_t *item = (wandder_item_t *)malloc(sizeof(wandder_item_t));

    item->parent = NULL;
    return item;
}

static int decode(wandder_decoder_t *dec, uint8_t *ptr, wandder_item_t **item,
        wandder_item_t *parent) {

    uint8_t tagbyte = *ptr;
    uint8_t shortlen;
    uint32_t prelen = 0;
    int i;

    if (*item == NULL || *item == parent) {
        *item = create_new_item(dec);
    }
    while (parent != NULL && ptr >= parent->valptr + parent->length) {
        /* Reached end of preceding sequence */
        wandder_item_t *tmp = parent;
        parent = parent->parent;

        if (tmp == dec->toplevel) {
            dec->toplevel = NULL;
        }
        if (tmp == dec->current) {
            dec->current = NULL;
        }
        free(tmp);

        if (parent == NULL) {
            /* Reached end of the top level sequence */
            return 0;
        }
    }

    if (parent == NULL) {
        (*item)->level = 0;
    } else {
        (*item)->level = parent->level + 1;
    }

    (*item)->parent = parent;

    /* First, let's try to figure out the tag type */

    if ((tagbyte & 0x1f) == 0x1f) {
        ptr ++;
        i = 0;
        prelen += 1;

        (*item)->identifier = (*ptr) & 0x7f;
        while ((*ptr) & 0x80) {
            ptr ++;
            prelen += 1;
            (*item)->identifier = ((*item)->identifier << 7);
            (*item)->identifier |= ((*ptr) & 0x7f);

            if (prelen >= 5) {
                fprintf(stderr, "libwandder does not support type fields longer than 4 bytes right now\n");
                return -1;
            }
        }
    } else {
        (*item)->identifier = (tagbyte & 0x1f);
        prelen += 1;
        ptr ++;
    }
    (*item)->identclass = ((tagbyte & 0xe0) >> 5);

    shortlen = *ptr;
    if ((shortlen & 0x80) == 0) {
        (*item)->length = (shortlen & 0x7f);
        prelen += 1;
        ptr ++;
    } else {
        uint8_t lenoctets = (shortlen & 0x7f);
        if (lenoctets > sizeof((*item)->length)) {
            fprintf(stderr, "libwandder does not support length fields longer than %zd bytes right now\n", sizeof((*item)->length));
            fprintf(stderr, "Tried to decode an item with a length field of %u bytes.\n", lenoctets);
            return -1;
        }
        ptr ++;
        (*item)->length = 0;
        for (i = 0; i < (int)lenoctets; i++) {
            (*item)->length = (*item)->length << 8;
            (*item)->length |= (*ptr);
            ptr ++;

        }
        prelen += (lenoctets + 1);
    }

    (*item)->preamblelen = prelen;
    (*item)->valptr = ptr;

    return 1;

}

static int first_decode(wandder_decoder_t *dec) {

    wandder_item_t *it = NULL;
    int ret;

    ret = decode(dec, dec->source, &it, NULL);
    if (ret <= 0) {
        return ret;
    }

    dec->toplevel = it;
    dec->current = it;

    dec->topptr = dec->source;
    if (IS_CONSTRUCTED(dec->current)) {
        dec->nextitem = dec->source + it->preamblelen;
        return it->preamblelen;
    }
    dec->nextitem = dec->source + it->length + it->preamblelen;

    return it->length + it->preamblelen;
}

int wandder_decode_next(wandder_decoder_t *dec) {
    int ret;

    /* If toplevel is NULL, this is the first run */
    if (dec->toplevel == NULL) {
        return first_decode(dec);
    }

    /* if current is a constructed type, the next item is the first child
     * of current */
    if ((IS_CONSTRUCTED(dec->current))) {
        ret = decode(dec, dec->nextitem, &(dec->current), dec->current);
    } else {
        /* if current is not a constructed type, use current's parent */
        ret = decode(dec, dec->nextitem, &(dec->current),
                dec->current->parent);
    }

    if (ret <= 0) {
        return ret;
    }
    if (IS_CONSTRUCTED(dec->current)) {
        dec->nextitem = dec->nextitem + dec->current->preamblelen;
        return dec->current->preamblelen;
    }

    dec->nextitem = dec->nextitem + dec->current->length +
            dec->current->preamblelen;

    return dec->current->length + dec->current->preamblelen;

}

const char *wandder_get_tag_string(wandder_decoder_t *dec) {

	uint8_t class;
	uint32_t ident;
    static char tmp[2048];

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

    if (!dec->current) {
        return WANDDER_CLASS_UNKNOWN;
    }

    return dec->current->identclass;
}

uint32_t wandder_get_identifier(wandder_decoder_t *dec) {

    if (dec->current) {
        return dec->current->identifier;
    }
    return 0xffffffff;
}

uint16_t wandder_get_level(wandder_decoder_t *dec) {
    if (dec->current) {
        return dec->current->level;
    }
    return 0xffff;
}

uint32_t wandder_get_itemlen(wandder_decoder_t *dec) {

    if (dec->current) {
        return dec->current->length;
    }
    return 0;
}

uint8_t *wandder_get_itemptr(wandder_decoder_t *dec) {
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
    int64_t intval = 0;
    uint32_t i = 0;

    for (i = 0; i < *length; i++) {
        if ( i == 8 ) {
            fprintf(stderr, "integer is too long for libwandder\n");
            *length = 0;
            return 0;
        }

        intval |= (*(start + i)) << (8 * (*length - 1 - i));
    }
    *length = i;
    return intval;
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
    *intlen = len;

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

struct timeval wandder_generalizedts_to_timeval(char *gts, int len) {
    struct timeval tv;
    struct tm tm;
    char *nxt = NULL;
    char *skipto = NULL;
    int ms = 0;
    int tzcorrect = 0;
    time_t current;

    tv.tv_sec = 0;
    tv.tv_usec = 0;

    if (len < 14) {
        fprintf(stderr, "Generalized time string %s is too short!\n", gts);
        return tv;
    }

    nxt = gts + 14;     /* YYYYmmddHHMMSS */

    if (*nxt == '.') {
        skipto = nxt;

        while (*skipto != 'Z' && *skipto != '-' && *skipto != '+') {
            if (skipto - gts > len) {
                fprintf(stderr, "Timezone missing from generalized time.\n");
                return tv;
            }
            skipto ++;
        }

        /* Assuming 3 digits here -- more (or less) are technically possible
         * though :( */
        if (sscanf(nxt, ".%d", &ms) != 1) {
            fprintf(stderr, "%s\n", nxt);
            fprintf(stderr, "Failed to parse milliseconds in generalized time.\n");
            return tv;
        }
    }

    if (strptime(gts, "%Y%m%d%H%M%S", &tm) == NULL) {
        fprintf(stderr, "strptime failed to parse generalized time: %s\n", gts);
        return tv;
    }


    current = time(NULL);
    switch(*skipto) {
        /* The time is going to be interpreted as UTC, so we'll need to
         * remove any timezone differences using TZ_TO_OFFSET. However, mktime
         * assumes local time so we'll need to also add the time difference
         * between us and UTC to get a sensible unix timestamp.
         */
        case 'Z':
            tzcorrect = localtime(&current)->tm_gmtoff;
            break;
        case '+':
            tzcorrect = localtime(&current)->tm_gmtoff - TZ_TO_OFFSET(skipto + 1);
            break;
        case '-':
            tzcorrect = localtime(&current)->tm_gmtoff + TZ_TO_OFFSET(skipto + 1);
            break;
    }

    tm.tm_gmtoff = 0;
    tv.tv_sec = mktime(&tm) + tzcorrect;
    tv.tv_usec = ms * 1000;
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
            space[0] = '\0';
            break;
        case WANDDER_TAG_OCTETSTRING:
        case WANDDER_TAG_PRINTABLE:
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
        case WANDDER_TAG_NULL:
        case WANDDER_TAG_OBJDESC:
        case WANDDER_TAG_REAL:
        case WANDDER_TAG_UTF8STR:
        case WANDDER_TAG_NUMERIC:
        case WANDDER_TAG_IA5:
        case WANDDER_TAG_UTCTIME:
        default:
            fprintf(stderr, "No stringify support for type %u just yet...\n",
                    datatype);
            return NULL;
    }

    return space;
}

static wandder_found_t *add_found_item(wandder_item_t *item,
        wandder_found_t *found, int targetid, uint16_t type) {

    if (found == NULL) {
        found = (wandder_found_t *)malloc(sizeof(wandder_found_t));
        found->list = (wandder_found_item_t *)malloc(
                sizeof(wandder_found_item_t) * 10);
        found->itemcount = 0;
        found->alloced = 10;
    }

    if (found->itemcount == found->alloced) {
        found->list = (wandder_found_item_t *)realloc(found->list,
                sizeof(wandder_found_item_t) * (found->alloced + 10));
        found->alloced += 10;
    }

    found->list[found->itemcount].item = (wandder_item_t *)malloc(
            sizeof(wandder_item_t));

    memcpy(found->list[found->itemcount].item, item, sizeof(wandder_item_t));
    found->list[found->itemcount].targetid = targetid;
    found->list[found->itemcount].interpretas = type;
    found->itemcount ++;

    return found;

}

void wandder_free_found(wandder_found_t *found) {

    int i;

    if (found == NULL) {
        return;
    }

    for (i = 0; i < found->itemcount; i++) {
        free(found->list[i].item);
    }
    free(found->list);
    free(found);
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
                actions->members[i].interpretas);
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

        *found = add_found_item(dec->current, *found, i, interpretas);
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
        if (wandder_get_class(dec) == WANDDER_CLASS_CONTEXT_PRIMITIVE) {
            act = &(actions->members[ident]);

            assert(act->descend == NULL);
            if (!wandder_get_valuestr(dec->current, space, 2048, act->interpretas)) {
                return -1;
            }

            printf("[%u] %u %s %s\n", ident, level, act->name, space);
        }

        if (wandder_get_class(dec) == WANDDER_CLASS_CONTEXT_CONSTRUCT) {
            act = &(actions->members[ident]);
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
