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

#ifndef LIBWANDDER_H_
#define LIBWANDDER_H_

#include <inttypes.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/time.h>

#define IS_CONSTRUCTED(x) ((x->identclass) & 0x01 ? 1: 0)
#define ALLOC_MEMBERS(x) x.members = (struct wandder_dump_action *)malloc( \
        sizeof(struct wandder_dump_action) * x.membercount);


/* Identifier classes */
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

/* Known tag types, i.e. data types for encoded values */
/* XXX Not all of these are fully implemented yet */
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
    WANDDER_TAG_BINARY_IP = 0x31,
};

/* Dumpers are used to describe hierarchy and data types for a particular
 * schema expressed in ASN.1, especially schemas that are primarily context
 * sensitive.
 *
 * By defining a dumper hierarchy, you can provide libwandder with
 * instructions on how to interpret each decoded field, e.g. field 4 in
 * a particular sequence should be treated as an integer. Container fields
 * (e.g. sequences within sequences) are represented by setting 'descend' to
 * point to a dumper that describes the strucutre of the child sequence.
 */
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

typedef struct wandder_itemblob wandder_itemblob_t;

struct wandder_itemblob {
    uint8_t *blob;
    size_t blobsize;
    size_t itemsize;
    uint32_t alloceditems;
    uint32_t nextavail;
    uint32_t released;

    wandder_itemblob_t *nextfree;
};

typedef struct wandder_itemhandler {
    uint32_t items_per_blob;
    size_t itemsize;
    int freelistavail;
    wandder_itemblob_t *current;
    wandder_itemblob_t *freelist;
    uint32_t unreleased;
    size_t pagesize;
} wandder_itemhandler_t;


/* Items are decoded fields extracted from the input stream.
 *
 * The item value itself remains a generic pointer -- if the class is not
 * universal, then a corresponding dumper will be required to interpret
 * the contents of that pointer correctly.
 */
typedef struct wandder_item wandder_item_t;

struct wandder_item {

    wandder_item_t *parent;
    uint32_t identifier;
    uint32_t preamblelen;
    uint32_t length;
    bool indefform;
    uint16_t level;
    uint8_t identclass;
    uint8_t *valptr;
    wandder_itemblob_t *memsrc;
    wandder_itemhandler_t *handler;

    wandder_item_t *cachednext;
    wandder_item_t *cachedchildren;
    uint8_t descend;
};


/* The decoder manages the overall decoding process. It maintains a pointer
 * to the most recently decoded item and the location in the input stream
 * that we have decoded up to.
 *
 * Almost all decoding operations will require a reference to a decoder.
 */
typedef struct wandder_decoder {

    wandder_itemhandler_t *item_handler;
    wandder_itemhandler_t *found_handler;
    wandder_itemhandler_t *foundlist_handler;
    wandder_item_t *toplevel;
    wandder_item_t *current;

    wandder_item_t *cacheditems;

    uint8_t *topptr;
    uint8_t *nextitem;

    uint8_t *source;
    uint32_t sourcelen;

    bool ownsource;
    uint32_t cachedts;
    char prevgts[16];
} wandder_decoder_t;


/* A target describes a particular field that one wants to find in a decoded
 * input stream. Fields are uniquely identified by their parent structure
 * (represented by the dumper describing that structure) and the identifier
 * for the requested item within the parent structure (e.g. set to 0 for
 * item id 0, 1 for item id 1 etc.).
 */
typedef struct wandder_search_target {
    wandder_dumper_t *parent;
    uint32_t itemid;
    bool found;         /* Will be set to true if this target is found */
} wandder_target_t;

/* Describes a successfully found item from a decoded input stream. Also
 * includes the interpretation instructions from the corresponding dumper,
 * so you can correctly interpret the item value.
 */
typedef struct wandder_found_item {
    wandder_item_t *item;
    int targetid;       /* Index in the search target array for this item */
    uint16_t interpretas;
} wandder_found_item_t;

/* A simple list of items extracted from a decoded input stream */
typedef struct wandder_found_items {
    wandder_found_item_t *list;
    int itemcount;
    int alloced;
    wandder_itemhandler_t *handler;
    wandder_itemblob_t *memsrc;
    wandder_itemhandler_t *list_handler;
    wandder_itemblob_t *list_memsrc;
} wandder_found_t;


/* Encoding is performed left to right, but the length values for each field
 * are calculated from inside outwards. Therefore, fields to be encoded are
 * staged as "pending" until all fields to be encoded have been pushed to the
 * encoder. Once we have all fields, we can correctly calculate the lengths
 * for each field and begin the encoding process proper.
 */
typedef struct wandder_pending wandder_pend_t;

typedef struct wandder_encode_job {
    uint8_t identclass;
    uint32_t identifier;
    uint32_t valalloced;
    uint32_t vallen;
    uint8_t *valspace;
    uint8_t encodeas;
    uint8_t preamblen;
    uint8_t *encodedspace;
    uint32_t encodedlen;
} wandder_encode_job_t;


struct wandder_pending {
    wandder_encode_job_t thisjob;
    uint32_t childrensize;

    wandder_pend_t *nextfree;
    wandder_pend_t *children;
    wandder_pend_t *lastchild;
    wandder_pend_t *siblings;
    wandder_pend_t *parent;
};

typedef struct wandder_encoded_result wandder_encoded_result_t;
typedef struct wandder_encoder wandder_encoder_t;

struct wandder_encoded_result {
    wandder_encoder_t *encoder;
    uint8_t *encoded;
    uint32_t len;
    uint32_t alloced;
    wandder_encoded_result_t *next;
};

/* The encoder manages the overall encoder process. It simply maintains the
 * full hierarchy of pending items and will encode them all once the user
 * indicates that all fields have been pushed to the encoder.
 *
 * Almost all encoding operations will require a reference to a encoder.
 */
struct wandder_encoder {
    wandder_pend_t *pendlist;
    wandder_pend_t *current;
    wandder_pend_t *quickfree_head;
    wandder_pend_t *quickfree_tail;
    wandder_pend_t *quickfree_pc_head;
    wandder_pend_t *quickfree_pc_tail;
    wandder_pend_t *freelist;
    wandder_pend_t *freeprecompute;
    wandder_encoded_result_t *freeresults;

    pthread_mutex_t mutex;
};


/* Encoding API
 * ----------------------------------------------------
 */
wandder_encoder_t *init_wandder_encoder();
void reset_wandder_encoder(wandder_encoder_t *enc);
void free_wandder_encoder(wandder_encoder_t *enc);

void wandder_encode_next(wandder_encoder_t *enc, uint8_t encodeas,
        uint8_t itemclass, uint32_t idnum, void *valptr, uint32_t vallen);
int wandder_encode_preencoded_value(wandder_encode_job_t *p, void *valptr,
        uint32_t vallen);
void wandder_encode_next_preencoded(wandder_encoder_t *enc,
        wandder_encode_job_t **jobs, int jobcount);
void wandder_encode_endseq(wandder_encoder_t *enc);
void wandder_encode_endseq_repeat(wandder_encoder_t *enc, int repeats);
wandder_encoded_result_t *wandder_encode_finish(wandder_encoder_t *enc);
void wandder_release_encoded_result(wandder_encoder_t *enc,
        wandder_encoded_result_t *res);
void wandder_release_encoded_results(wandder_encoder_t *enc,
        wandder_encoded_result_t *res, wandder_encoded_result_t *tail);

/* Decoding API
 * ----------------------------------------------------
 */
wandder_decoder_t *init_wandder_decoder(wandder_decoder_t *dec,
        uint8_t *source, uint32_t len, bool copy);
void wandder_reset_decoder(wandder_decoder_t *dec);
void free_wandder_decoder(wandder_decoder_t *dec);
int wandder_decode_next(wandder_decoder_t *dec);
int wandder_decode_skip(wandder_decoder_t *dec);
int wandder_decode_sequence_until(wandder_decoder_t *dec, uint32_t ident);
uint8_t wandder_get_class(wandder_decoder_t *dec);
uint32_t wandder_get_identifier(wandder_decoder_t *dec);
uint16_t wandder_get_level(wandder_decoder_t *dec);
uint32_t wandder_get_itemlen(wandder_decoder_t *dec);
uint8_t *wandder_get_itemptr(wandder_decoder_t *dec);
char * wandder_get_valuestr(wandder_item_t *c, char *space, uint16_t len,
        uint8_t interpretas);
const char *wandder_get_tag_string(wandder_decoder_t *dec);

struct timeval wandder_generalizedts_to_timeval(wandder_decoder_t *dec,
        char *gts, int len);
int64_t wandder_get_integer_value(wandder_item_t *c, uint32_t *intlen);
int wandder_timeval_to_generalizedts(struct timeval tv, char *gts, int space);
int wandder_decode_dump(wandder_decoder_t *dec, uint16_t level,
        wandder_dumper_t *actions, char *name);

/* Decode-search API
 * ----------------------------------------------------
 */
int wandder_search_items(wandder_decoder_t *dec, uint16_t level,
        wandder_dumper_t *actions, wandder_target_t *targets,
        int targetcount, wandder_found_t **found, int stopthresh);
void wandder_free_found(wandder_found_t *found);
#endif


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

