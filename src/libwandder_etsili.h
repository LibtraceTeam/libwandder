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

#ifndef LIBWANDDER_ETSILI_H_
#define LIBWANDDER_ETSILI_H_

#include <libwandder.h>

#define WANDDER_ETSILI_PSDOMAINID (etsi_lipsdomainid)

#define MEMCPYPREENCODE(ptr, itembuf) {memcpy(ptr, itembuf->buf, itembuf->len); ptr+=itembuf->len;}

#define ENDCONSTRUCTEDBLOCK(ptr,num) {for (int uniuqevari = 0; uniuqevari < num*2; uniuqevari++){*ptr = 0;ptr+=1;}}
//memset(ptr, 0, num*2);ptr+=num*2;

extern const uint8_t etsi_lipsdomainid[9];

typedef struct wandder_etsistack {

    int alloced;
    int current;
    wandder_dumper_t **stk;
    int *atthislevel;
} wandder_etsi_stack_t;

typedef struct wandder_etsispec {
    wandder_dumper_t ipaddress;
    wandder_dumper_t ipvalue;
    wandder_dumper_t nationalipmmiri;
    wandder_dumper_t h323content;
    wandder_dumper_t h323message;
    wandder_dumper_t sipmessage;
    wandder_dumper_t ipmmiricontents;
    wandder_dumper_t ipmmiri;
    wandder_dumper_t ipiriid;
    wandder_dumper_t ipiricontents;
    wandder_dumper_t ipiri;
    wandder_dumper_t iricontents;
    wandder_dumper_t iripayload;
    wandder_dumper_t netelid;
    wandder_dumper_t root;
    wandder_dumper_t netid;
    wandder_dumper_t cid;
    wandder_dumper_t msts;
    wandder_dumper_t cccontents;
    wandder_dumper_t ccpayloadseq;
    wandder_dumper_t ccpayload;
    wandder_dumper_t operatorleamessage;
    wandder_dumper_t option;
    wandder_dumper_t optionseq;
    wandder_dumper_t optionreq;
    wandder_dumper_t optionresp;
    wandder_dumper_t inclseqnos;
    wandder_dumper_t integritycheck;
    wandder_dumper_t tripayload;
    wandder_dumper_t payload;
    wandder_dumper_t psheader;
    wandder_dumper_t pspdu;
    wandder_dumper_t ipmmcc;
    wandder_dumper_t ipcc;
    wandder_dumper_t ipcccontents;
    wandder_dumper_t iripayloadseq;

    wandder_decoder_t *dec;
    wandder_etsi_stack_t *stack;

    uint8_t decstate;
} wandder_etsispec_t;

typedef enum body_type {
    WANDDER_ETSILI_EMPTY,
    WANDDER_ETSILI_IPCC,
    WANDDER_ETSILI_IPMMCC,
    WANDDER_ETSILI_IPIRI,
    WANDDER_ETSILI_IPMMIRI,
} body_type_t;

typedef enum {
    ETSILI_IRI_BEGIN = 1,
    ETSILI_IRI_END = 2,
    ETSILI_IRI_CONTINUE = 3,
    ETSILI_IRI_REPORT = 4
} etsili_iri_type_t;

typedef struct wandder_pshdr {
    uint8_t* cin;
    uint8_t* seqno;
    uint8_t* sec;
    uint8_t* usec;
    uint8_t* end;
} wandder_pshdr_t;

typedef struct wandder_ipcc_body {
    uint8_t* dir;
    uint8_t* ipcontent;
} wandder_ipcc_body_t;

typedef struct wandder_ipmmcc_body {
    uint8_t* dir;
    uint8_t* ipcontent;
} wandder_ipmmcc_body_t;

typedef struct wandder_ipiri_body {
    uint8_t* iritype;
    uint8_t* params;
} wandder_ipiri_body_t;

typedef struct wandder_ipmmiri_body {
    uint8_t* iritype;
    uint8_t* ipcontent;
} wandder_ipmmiri_body_t;

typedef struct wandber_etsili_top {
    uint8_t* buf;
    size_t len;
    size_t alloc_len;
    wandder_pshdr_t header;
    body_type_t body_type;
    union {
        wandder_ipcc_body_t ipcc;
        wandder_ipmmcc_body_t ipmmcc;
        wandder_ipmmiri_body_t ipmmiri;
        wandder_ipiri_body_t ipiri;
    } body;
} wandber_etsili_top_t;


typedef enum {
    OPENLI_PREENCODE_USEQUENCE,
    OPENLI_PREENCODE_CSEQUENCE_0,
    OPENLI_PREENCODE_CSEQUENCE_1,
    OPENLI_PREENCODE_CSEQUENCE_2,
    OPENLI_PREENCODE_CSEQUENCE_3,
    OPENLI_PREENCODE_CSEQUENCE_7,	/* Microsecond timestamp */
    OPENLI_PREENCODE_CSEQUENCE_11,  /* IPMMIRI */
    OPENLI_PREENCODE_CSEQUENCE_12,  /* IPMMCC */
    OPENLI_PREENCODE_PSDOMAINID,
    OPENLI_PREENCODE_LIID,
    OPENLI_PREENCODE_AUTHCC,
    OPENLI_PREENCODE_OPERATORID,
    OPENLI_PREENCODE_NETWORKELEMID,
    OPENLI_PREENCODE_DELIVCC,
    OPENLI_PREENCODE_INTPOINTID,
    OPENLI_PREENCODE_TVCLASS,
    OPENLI_PREENCODE_IPMMIRIOID,
    OPENLI_PREENCODE_IPCCOID,
    OPENLI_PREENCODE_IPIRIOID,
    OPENLI_PREENCODE_IPMMCCOID,
    OPENLI_PREENCODE_DIRFROM,
    OPENLI_PREENCODE_DIRTO,
    OPENLI_PREENCODE_DIRUNKNOWN,
    OPENLI_PREENCODE_LAST

} preencode_index_t;

typedef struct etsili_intercept_details {
    char *liid;
    char *authcc;
    char *delivcc;
    char *intpointid;
    char *operatorid;
    char *networkelemid;
} etsili_intercept_details_t;

enum {
    WANDDER_IRI_CONTENT_IP,
    WANDDER_IRI_CONTENT_SIP,
};

wandder_etsispec_t *wandder_create_etsili_decoder(void);
void wandder_free_etsili_decoder(wandder_etsispec_t *dec);
void wandder_attach_etsili_buffer(wandder_etsispec_t *dec, uint8_t *buffer,
        uint32_t len, bool copy);

wandder_dumper_t *wandder_get_etsili_structure(wandder_etsispec_t *dec);

wandder_decoder_t *wandder_get_etsili_base_decoder(wandder_etsispec_t *dec);
struct timeval wandder_etsili_get_header_timestamp(wandder_etsispec_t *dec);
uint32_t wandder_etsili_get_pdu_length(wandder_etsispec_t *dec);
char *wandder_etsili_get_next_fieldstr(wandder_etsispec_t *dec, char *space,
        int spacelen);
uint8_t *wandder_etsili_get_cc_contents(wandder_etsispec_t *dec, uint32_t *len,
        char *name, int namelen);
uint8_t *wandder_etsili_get_iri_contents(wandder_etsispec_t *dec,
        uint32_t *len, uint8_t *ident, char *name, int namelen);
char *wandder_etsili_get_liid(wandder_etsispec_t *dec, char *space,
        int spacelen);
uint32_t wandder_etsili_get_cin(wandder_etsispec_t *dec);
int wandder_etsili_is_keepalive(wandder_etsispec_t *etsidec);
int wandder_etsili_is_keepalive_response(wandder_etsispec_t *etsidec);
int64_t wandder_etsili_get_sequence_number(wandder_etsispec_t *etsidec);




void encode_etsi_ipcc(
        wandder_buf_t **precomputed, int64_t cin, int64_t seqno,
        struct timeval *tv, void *ipcontents, uint32_t iplen, uint8_t dir,
        wandber_etsili_top_t *top);
void encode_etsi_ipmmcc(
        wandder_buf_t **precomputed, int64_t cin, int64_t seqno,
        struct timeval *tv, void *ipcontents, uint32_t iplen, uint8_t dir,
        wandber_etsili_top_t *top);

void encode_etsi_ipmmiri(
        wandder_buf_t **precomputed, int64_t cin, int64_t seqno,
        struct timeval *tv, void *ipcontents, uint32_t iplen, etsili_iri_type_t iritype,
        wandber_etsili_top_t *top);

void encode_etsi_ipiri(
        wandder_buf_t **precomputed, int64_t cin, int64_t seqno,
        struct timeval *tv, void* params, etsili_iri_type_t iritype,
        wandber_etsili_top_t *top);

void etsili_preencode_static_fields_ber(
        wandder_buf_t **pendarray, etsili_intercept_details_t *details);
void etsili_clear_preencoded_fields_ber(wandder_buf_t **pendarray);



#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
