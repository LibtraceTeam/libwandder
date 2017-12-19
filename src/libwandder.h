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

#ifndef LIBWANDDER_H_
#define LIBWANDDER_H_

#include <inttypes.h>
#include <stdbool.h>

#define IS_CONSTRUCTED(x) ((x->identclass) & 0x01 ? 1: 0)
#define ALLOC_MEMBERS(x) x.members = (struct wandder_dump_action *)malloc( \
        sizeof(struct wandder_dump_action) * x.membercount);


enum {
    WANDDER_CLASS_UNIVERSAL_PRIMITIVE = 0,
    WANDDER_CLASS_UNIVERSAL_CONSTRUCT = 1,
    WANDDER_CLASS_APPLICATION_PRIMITIVE = 2,
    WANDDER_CLASS_APPLICATION_CONSTRUCT = 3,
    WANDDER_CLASS_CONTEXT_PRIMITIVE = 4,
    WANDDER_CLASS_CONTEXT_CONSTRUCT = 5,
    WANDDER_CLASS_PRIVATE_PRIMITIVE = 6,
    WANDDER_CLASS_PRIVATE_CONSTRUCT = 7,
    WANDDER_CLASS_UNKNOWN = 255,
};

enum {
    WANDDER_TAG_BOOLEAN = 0x01,
    WANDDER_TAG_INTEGER = 0x02,
    WANDDER_TAG_BITSTRING = 0x03,
    WANDDER_TAG_OCTETSTRING = 0x04,
    WANDDER_TAG_NULL = 0x05,
    WANDDER_TAG_OID = 0x06,
    WANDDER_TAG_OBJDESC = 0x07,
    WANDDER_TAG_REAL = 0x09,
    WANDDER_TAG_ENUM = 0x0A,
    WANDDER_TAG_UTF8STR = 0x0C,
    WANDDER_TAG_RELATIVEOID = 0x0D,
    WANDDER_TAG_SEQUENCE = 0x10,
    WANDDER_TAG_SET = 0x11,
    WANDDER_TAG_NUMERIC = 0x12,
    WANDDER_TAG_PRINTABLE = 0x13,
    WANDDER_TAG_IA5 = 0x16,
    WANDDER_TAG_UTCTIME = 0x17,
    WANDDER_TAG_GENERALTIME = 0x18,

    /* Custom tag types, use only for "interpret as" values. */
    WANDDER_TAG_IPPACKET = 0x30,
};

typedef struct wandder_dumper wandder_dumper_t;

struct wandder_dump_action {

    char *name;
    wandder_dumper_t *descend;
    uint16_t interpretas;

};

struct wandder_dumper {

    uint16_t membercount;
    struct wandder_dump_action *members;
    struct wandder_dump_action sequence;

};

extern struct wandder_dump_action WANDDER_NOACTION;

typedef struct wandder_item wandder_item_t;

struct wandder_item {

    wandder_item_t *parent;
    uint32_t identifier;
    uint32_t preamblelen;
    uint32_t length;
    uint16_t level;
    uint8_t identclass;
    uint8_t *valptr;

};


typedef struct wandder_decoder {

    wandder_item_t *toplevel;
    wandder_item_t *current;

    uint8_t *topptr;
    uint8_t *nextitem;

    uint8_t *source;
    uint32_t sourcelen;

    bool ownsource;

} wandder_decoder_t;

typedef struct wandder_search_target {
    wandder_dumper_t *parent;
    uint32_t itemid;
    bool found;
} wandder_target_t;

typedef struct wandder_found_item {
    wandder_item_t *item;
    int targetid;
    uint16_t interpretas;
} wandder_found_item_t;

typedef struct wandder_found_items {
    wandder_found_item_t *list;
    int itemcount;
    int alloced;
} wandder_found_t;


void init_wandder_decoder(wandder_decoder_t *dec, uint8_t *source, uint32_t len,
        bool copy);
void wandder_reset_decoder(wandder_decoder_t *dec);
void free_wandder_decoder(wandder_decoder_t *dec);
int wandder_decode_next(wandder_decoder_t *dec);
uint8_t wandder_get_class(wandder_decoder_t *dec);
uint32_t wandder_get_identifier(wandder_decoder_t *dec);
uint16_t wandder_get_level(wandder_decoder_t *dec);
uint32_t wandder_get_itemlen(wandder_decoder_t *dec);
uint8_t *wandder_get_itemptr(wandder_decoder_t *dec);
char * wandder_get_valuestr(wandder_item_t *c, char *space, uint16_t len,
        uint8_t interpretas);
const char *wandder_get_tag_string(wandder_decoder_t *dec);

struct timeval wandder_generalizedts_to_timeval(char *gts, int len);
int64_t wandder_get_integer_value(wandder_item_t *c, uint32_t *intlen);



int wandder_decode_dump(wandder_decoder_t *dec, uint16_t level,
        wandder_dumper_t *actions, char *name);

int wandder_search_items(wandder_decoder_t *dec, uint16_t level,
        wandder_dumper_t *actions, wandder_target_t *targets,
        int targetcount, wandder_found_t **found, int stopthresh);
void wandder_free_found(wandder_found_t *found);
#endif


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

