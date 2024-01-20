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
#include <stdint.h>
#include <uthash.h>

#define WANDDER_ETSILI_PSDOMAINID (etsi_lipsdomainid)

#define MEMCPYPREENCODE(ptr, itembuf) {memcpy(ptr, itembuf->buf, itembuf->len); ptr+=itembuf->len;}

#define ENDCONSTRUCTEDBLOCK(ptr,num) memset(ptr, 0, num*2);ptr+=num*2;

extern const uint8_t etsi_lipsdomainid[8];

typedef struct wandder_etsistack {

    int alloced;
    int current;
    wandder_dumper_t **stk;
    int *atthislevel;
} wandder_etsi_stack_t;

typedef struct wandder_etsispec {
    wandder_dumper_t ipaddress;
    wandder_dumper_t datanodeaddress;
    wandder_dumper_t timestamp;
    wandder_dumper_t localtimestamp;
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
    wandder_dumper_t umtsiri;
    wandder_dumper_t umtsiri_params;
    wandder_dumper_t iricontents;
    wandder_dumper_t iripayload;
    wandder_dumper_t netelid;
    wandder_dumper_t root;
    wandder_dumper_t linetid;
    wandder_dumper_t networkidentifier;
    wandder_dumper_t location;
    wandder_dumper_t partyinfo;
    wandder_dumper_t partyidentity;
    wandder_dumper_t servicesdatainfo;
    wandder_dumper_t gprsparams;
    wandder_dumper_t hi2op_cid;
    wandder_dumper_t hi2op_netid;
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
    wandder_dumper_t integritycheck;
    wandder_dumper_t tripayload;
    wandder_dumper_t payload;
    wandder_dumper_t psheader;
    wandder_dumper_t pspdu;
    wandder_dumper_t ipmmcc;
    wandder_dumper_t ipcc;
    wandder_dumper_t ipcccontents;
    wandder_dumper_t iripayloadseq;
    wandder_dumper_t hi1operation;
    wandder_dumper_t hi1notification;
    wandder_dumper_t emailiri;
    wandder_dumper_t emailcc;
    wandder_dumper_t emailrecipients;
    wandder_dumper_t emailrecipientsingle;
    wandder_dumper_t aaainformation;
    wandder_dumper_t pop3aaainformation;
    wandder_dumper_t asmtpaaainformation;
    wandder_dumper_t encryptioncontainer;
    wandder_dumper_t encryptedpayload;
    wandder_dumper_t encryptedpayloadroot;
    wandder_dumper_t additionalsignallingseq;
    wandder_dumper_t additionalsignalling;
    wandder_dumper_t lipspdulocation;
    wandder_dumper_t epslocation;

    wandder_decoder_t *dec;
    wandder_etsi_stack_t *stack;

    uint8_t decstate;
    uint8_t ccformat;

    char *decryption_key;
    int encrypt_method;
    uint8_t *decrypted;
    uint32_t decrypt_size;
    wandder_decoder_t *decrypt_dec;
    wandder_etsi_stack_t *decrypt_stack;
    uint8_t *saved_decrypted_payload;
    uint32_t saved_payload_size;
    char *saved_payload_name;
} wandder_etsispec_t;

typedef enum {
    WANDDER_ETSILI_IRI_BEGIN = 1,
    WANDDER_ETSILI_IRI_END = 2,
    WANDDER_ETSILI_IRI_CONTINUE = 3,
    WANDDER_ETSILI_IRI_REPORT = 4
} wandder_etsili_iri_type_t;

enum {
    WANDDER_IPIRI_ID_PRINTABLE = 0,
    WANDDER_IPIRI_ID_MAC = 1,
    WANDDER_IPIRI_ID_IPADDR = 2,
};

typedef struct wandder_pshdr {
    uint8_t* buf;
    size_t len;
    uint8_t* cin;
    uint8_t* seqno;
    uint8_t* sec;
    uint8_t* usec;
    uint8_t* end;
} wandder_pshdr_t;

typedef struct wandder_etsili_child wandder_etsili_child_t;

typedef struct wandder_etsili_child_freelist {
    pthread_mutex_t mutex;
    wandder_etsili_child_t * first;
    int counter;
    int marked_for_delete;
} wandder_etsili_child_freelist_t;

typedef struct wandder_generic_body {
    uint8_t* buf;
    size_t len;
    size_t alloc_len;
    uint8_t* meta;
    uint8_t* data;
    wandder_etsili_child_freelist_t * flist;
} wandder_generic_body_t;

typedef struct wandder_etsili_top {
    wandder_pshdr_t header;
    wandder_generic_body_t ipcc;
    wandder_generic_body_t ipmmcc;
    wandder_generic_body_t ipmmiri;
    wandder_generic_body_t ipiri;
    wandder_generic_body_t umtscc;
    wandder_generic_body_t umtsiri;
    size_t increment_len;
    wandder_buf_t **preencoded;
} wandder_etsili_top_t;

struct wandder_etsili_child {
    uint8_t* buf;
    size_t len;
    size_t alloc_len;
    wandder_pshdr_t header;
    wandder_generic_body_t body;
    wandder_etsili_top_t * owner;

    wandder_etsili_child_freelist_t * flist;
    wandder_etsili_child_t * nextfree;
};

typedef enum {
    WANDDER_PREENCODE_USEQUENCE,
    WANDDER_PREENCODE_CSEQUENCE_0,
    WANDDER_PREENCODE_CSEQUENCE_1,
    WANDDER_PREENCODE_CSEQUENCE_2,
    WANDDER_PREENCODE_CSEQUENCE_3,
    WANDDER_PREENCODE_CSEQUENCE_4,
    WANDDER_PREENCODE_CSEQUENCE_5,
    WANDDER_PREENCODE_CSEQUENCE_7,	/* Microsecond timestamp */
    WANDDER_PREENCODE_CSEQUENCE_8,
    WANDDER_PREENCODE_CSEQUENCE_9,
    WANDDER_PREENCODE_CSEQUENCE_11,  /* IPMMIRI */
    WANDDER_PREENCODE_CSEQUENCE_12,  /* IPMMCC */
    WANDDER_PREENCODE_CSEQUENCE_13,
    WANDDER_PREENCODE_CSEQUENCE_26,
    WANDDER_PREENCODE_PSDOMAINID,
    WANDDER_PREENCODE_LIID,
    WANDDER_PREENCODE_AUTHCC,
    WANDDER_PREENCODE_OPERATORID,
    WANDDER_PREENCODE_NETWORKELEMID,
    WANDDER_PREENCODE_DELIVCC,
    WANDDER_PREENCODE_INTPOINTID,
    WANDDER_PREENCODE_TVCLASS,
    WANDDER_PREENCODE_IPMMIRIOID,
    WANDDER_PREENCODE_IPCCOID,
    WANDDER_PREENCODE_IPIRIOID,
    WANDDER_PREENCODE_UMTSIRIOID,
    WANDDER_PREENCODE_IPMMCCOID,
    WANDDER_PREENCODE_DIRFROM,
    WANDDER_PREENCODE_DIRTO,
    WANDDER_PREENCODE_DIRUNKNOWN,
    WANDDER_PREENCODE_LIID_LEN,
    WANDDER_PREENCODE_LAST

} wandder_preencode_index_t;

enum {
    WANDDER_IPIRI_CONTENTS_ACCESS_EVENT_TYPE = 0,
    WANDDER_IPIRI_CONTENTS_TARGET_USERNAME = 1,
    WANDDER_IPIRI_CONTENTS_INTERNET_ACCESS_TYPE = 2,
    WANDDER_IPIRI_CONTENTS_IPVERSION = 3,
    WANDDER_IPIRI_CONTENTS_TARGET_IPADDRESS = 4,
    WANDDER_IPIRI_CONTENTS_TARGET_NETWORKID = 5,
    WANDDER_IPIRI_CONTENTS_TARGET_CPEID = 6,
    WANDDER_IPIRI_CONTENTS_TARGET_LOCATION = 7,
    WANDDER_IPIRI_CONTENTS_POP_PORTNUMBER = 8,
    WANDDER_IPIRI_CONTENTS_CALLBACK_NUMBER = 9,
    WANDDER_IPIRI_CONTENTS_STARTTIME = 10,
    WANDDER_IPIRI_CONTENTS_ENDTIME = 11,
    WANDDER_IPIRI_CONTENTS_ENDREASON = 12,
    WANDDER_IPIRI_CONTENTS_OCTETS_RECEIVED = 13,
    WANDDER_IPIRI_CONTENTS_OCTETS_TRANSMITTED = 14,
    WANDDER_IPIRI_CONTENTS_RAW_AAA_DATA = 15,
    WANDDER_IPIRI_CONTENTS_EXPECTED_ENDTIME = 16,
    WANDDER_IPIRI_CONTENTS_POP_PHONENUMBER = 17,
    WANDDER_IPIRI_CONTENTS_POP_IDENTIFIER = 18,
    WANDDER_IPIRI_CONTENTS_POP_IPADDRESS = 19,
    WANDDER_IPIRI_CONTENTS_NATIONAL_IPIRI_PARAMETERS = 20,
    WANDDER_IPIRI_CONTENTS_ADDITIONAL_IPADDRESS = 21,
    WANDDER_IPIRI_CONTENTS_AUTHENTICATION_TYPE = 22,
    WANDDER_IPIRI_CONTENTS_OTHER_TARGET_IDENTIFIERS = 23,
};

enum {
        WANDDER_UMTSIRI_CONTENTS_IMSI = 1,
        WANDDER_UMTSIRI_CONTENTS_MSISDN = 2,
        WANDDER_UMTSIRI_CONTENTS_IMEI = 3,
        WANDDER_UMTSIRI_CONTENTS_APNAME = 4,
        WANDDER_UMTSIRI_CONTENTS_TAI = 5,
        WANDDER_UMTSIRI_CONTENTS_ECGI = 6,
        WANDDER_UMTSIRI_CONTENTS_PDP_ADDRESS = 7,
        WANDDER_UMTSIRI_CONTENTS_EVENT_TYPE = 8,
        WANDDER_UMTSIRI_CONTENTS_EVENT_TIME = 9,
        WANDDER_UMTSIRI_CONTENTS_LOCATION_TIME = 10,
        WANDDER_UMTSIRI_CONTENTS_GPRS_CORRELATION = 11,
        WANDDER_UMTSIRI_CONTENTS_IRI_TYPE = 12,
        WANDDER_UMTSIRI_CONTENTS_GPRS_ERROR_CODE = 13,
        WANDDER_UMTSIRI_CONTENTS_GGSN_IPADDRESS = 14,
        WANDDER_UMTSIRI_CONTENTS_INITIATOR = 15,
        WANDDER_UMTSIRI_CONTENTS_OPERATOR_IDENTIFIER = 16,
        WANDDER_UMTSIRI_CONTENTS_PDPTYPE = 17,
        WANDDER_UMTSIRI_CONTENTS_CGI = 18,
        WANDDER_UMTSIRI_CONTENTS_SAI = 19,
};

enum {
    WANDDER_UMTSIRI_EVENT_TYPE_PDPCONTEXT_ACTIVATION = 1,
    WANDDER_UMTSIRI_EVENT_TYPE_START_WITH_PDPCONTEXT_ACTIVE = 2,
    WANDDER_UMTSIRI_EVENT_TYPE_PDPCONTEXT_DEACTIVATION = 4,
    WANDDER_UMTSIRI_EVENT_TYPE_PDPCONTEXT_MODIFICATION = 13,
};

enum {
    WANDDER_EMAIL_STATUS_UNKNOWN = 1,
    WANDDER_EMAIL_STATUS_FAILED = 2,
    WANDDER_EMAIL_STATUS_SUCCESS = 3
};

enum {
    WANDDER_ENCRYPTION_TYPE_NOT_STATED = 0,
    WANDDER_ENCRYPTION_TYPE_NONE = 1,
    WANDDER_ENCRYPTION_TYPE_NATIONAL = 2,
    WANDDER_ENCRYPTION_TYPE_AES_192_CBC = 3,
    WANDDER_ENCRYPTION_TYPE_AES_256_CBC = 4,
    WANDDER_ENCRYPTION_TYPE_BLOWFISH_192_CBC = 5,
    WANDDER_ENCRYPTION_TYPE_BLOWFISH_256_CBC = 6,
    WANDDER_ENCRYPTION_TYPE_THREEDES_CBC = 7,
};

enum {
    WANDDER_EMAIL_EVENT_SEND = 1,
    WANDDER_EMAIL_EVENT_RECEIVE = 2,
    WANDDER_EMAIL_EVENT_DOWNLOAD = 3,
    WANDDER_EMAIL_EVENT_LOGON_ATTEMPT = 4,
    WANDDER_EMAIL_EVENT_LOGON = 5,
    WANDDER_EMAIL_EVENT_LOGON_FAILURE = 6,
    WANDDER_EMAIL_EVENT_LOGOFF = 7,
    WANDDER_EMAIL_EVENT_PARTIAL_DOWNLOAD = 8,
    WANDDER_EMAIL_EVENT_UPLOAD = 9,
};

enum {
    WANDDER_EMAILIRI_CONTENTS_EVENT_TYPE = 1,
    WANDDER_EMAILIRI_CONTENTS_CLIENT_ADDRESS = 2,
    WANDDER_EMAILIRI_CONTENTS_SERVER_ADDRESS = 3,
    WANDDER_EMAILIRI_CONTENTS_CLIENT_PORT = 4,
    WANDDER_EMAILIRI_CONTENTS_SERVER_PORT = 5,
    WANDDER_EMAILIRI_CONTENTS_SERVER_OCTETS_SENT = 6,
    WANDDER_EMAILIRI_CONTENTS_CLIENT_OCTETS_SENT = 7,
    WANDDER_EMAILIRI_CONTENTS_PROTOCOL_ID = 8,
    WANDDER_EMAILIRI_CONTENTS_SENDER = 9,
    WANDDER_EMAILIRI_CONTENTS_RECIPIENTS = 10,
    WANDDER_EMAILIRI_CONTENTS_STATUS = 11,
    WANDDER_EMAILIRI_CONTENTS_TOTAL_RECIPIENTS = 12,
    WANDDER_EMAILIRI_CONTENTS_MESSAGE_ID = 13,
    WANDDER_EMAILIRI_CONTENTS_NATIONAL_PARAMETER = 14,
    WANDDER_EMAILIRI_CONTENTS_NATIONAL_ASN1_PARAMETERS = 15,
    WANDDER_EMAILIRI_CONTENTS_AAA_INFORMATION = 16,
    WANDDER_EMAILIRI_CONTENTS_SENDER_VALIDITY = 17,
};


typedef struct wandder_etsili_generic wandder_etsili_generic_t;
typedef struct wandder_etsili_generic_freelist wandder_etsili_generic_freelist_t;

struct wandder_etsili_generic {
    uint8_t itemnum;
    uint16_t itemlen;
    uint8_t *itemptr;
    uint16_t alloced;

    UT_hash_handle hh;
    wandder_etsili_generic_t *nextfree;
    wandder_etsili_generic_freelist_t *owner;
};

struct wandder_etsili_generic_freelist {
    wandder_etsili_generic_t *first;
    pthread_mutex_t mutex;
    uint8_t needmutex;
};

typedef struct wandder_etsili_intercept_details {
    char *liid;
    char *authcc;
    char *delivcc;
    char *intpointid;
    char *operatorid;
    char *networkelemid;
} wandder_etsili_intercept_details_t;

enum {
    WANDDER_IRI_CONTENT_IP,
    WANDDER_IRI_CONTENT_SIP,
};

typedef struct wandder_etsili_ipaddress {
    uint8_t iptype;
    uint8_t assignment;
    uint8_t v6prefixlen;
    uint32_t v4subnetmask;

    uint8_t valtype;
    uint8_t *ipvalue;
} wandder_etsili_ipaddress_t;

typedef struct wandder_ipiri_id {
    uint8_t type;
    union {
        char *printable;
        uint8_t mac[6];
        wandder_etsili_ipaddress_t *ip;
    } content;
} wandder_ipiri_id_t;

enum {
    WANDDER_IPADDRESS_REP_BINARY = 1,
    WANDDER_IPADDRESS_REP_TEXT = 2,
};

enum {
    WANDDER_IPADDRESS_ASSIGNED_STATIC = 1,
    WANDDER_IPADDRESS_ASSIGNED_DYNAMIC = 2,
    WANDDER_IPADDRESS_ASSIGNED_UNKNOWN = 3,
};
enum {
    WANDDER_IPADDRESS_VERSION_4 = 0,
    WANDDER_IPADDRESS_VERSION_6 = 1,
};

enum {
    WANDDER_ETSILI_CC_FORMAT_UNKNOWN = 0,
    WANDDER_ETSILI_CC_FORMAT_IP = 1,
    WANDDER_ETSILI_CC_FORMAT_APPLICATION = 2,
};

wandder_etsispec_t *wandder_create_etsili_decoder(void);
void wandder_free_etsili_decoder(wandder_etsispec_t *dec);
void wandder_attach_etsili_buffer(wandder_etsispec_t *dec, uint8_t *buffer,
        uint32_t len, bool copy);

int wandder_set_etsili_decryption_key(wandder_etsispec_t *dec, char *key);
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
uint8_t wandder_etsili_get_cc_format(wandder_etsispec_t *etsidec);


wandder_etsili_top_t* wandder_encode_init_top_ber (
            wandder_encoder_ber_t* enc_ber, 
            wandder_etsili_intercept_details_t* intdetails);
void wandder_free_top(wandder_etsili_top_t *top);
wandder_etsili_child_t *wandder_etsili_create_child(wandder_etsili_top_t* top, 
        wandder_generic_body_t * body);
void wandder_free_child(wandder_etsili_child_t * child);

void wandder_encode_etsi_ipcc_ber(
        int64_t cin, int64_t seqno,
        struct timeval *tv, void *ipcontents, size_t iplen, uint8_t dir,
        wandder_etsili_child_t * child);
void wandder_encode_etsi_ipmmcc_ber(
        int64_t cin, int64_t seqno,
        struct timeval *tv, void *ipcontents, size_t iplen, uint8_t dir,
        wandder_etsili_child_t * child);
void wandder_encode_etsi_ipmmiri_ber(
        int64_t cin, int64_t seqno,
        struct timeval *tv, void *ipcontents, size_t iplen, 
        wandder_etsili_iri_type_t iritype, uint8_t *ipsrc, uint8_t *ipdest,
        int ipfamily,
        wandder_etsili_child_t * child);
void wandder_encode_etsi_ipiri_ber(
        int64_t cin, int64_t seqno,
        struct timeval *tv, void* params, wandder_etsili_iri_type_t iritype,
        wandder_etsili_child_t * child);

void wandder_encode_etsi_umtsiri_ber(
        int64_t cin, int64_t seqno,
        struct timeval* tv, void* params, wandder_etsili_iri_type_t iritype,
        wandder_etsili_child_t * child);
void wandder_encode_etsi_umtscc_ber (
        int64_t cin, int64_t seqno,
        struct timeval* tv, void* ipcontents, size_t iplen, uint8_t dir,
        wandder_etsili_child_t * child);

void wandder_init_etsili_ipcc(
        wandder_encoder_ber_t* enc_ber,
        wandder_etsili_top_t* top);
void wandder_init_etsili_ipmmcc(
        wandder_encoder_ber_t* enc_ber,
        wandder_etsili_top_t* top);
void wandder_init_etsili_ipiri(
        wandder_encoder_ber_t* enc_ber,
        wandder_etsili_top_t* top);
void wandder_init_etsili_ipmmiri(
        wandder_encoder_ber_t* enc_ber,
        wandder_etsili_top_t* top);
void wandder_init_etsili_umtscc(
        wandder_encoder_ber_t* enc_ber,
        wandder_etsili_top_t* top);
void wandder_init_etsili_umtsiri(
        wandder_encoder_ber_t* enc_ber,
        wandder_etsili_top_t* top);

wandder_etsili_child_freelist_t *wandder_create_etsili_child_freelist();
wandder_etsili_child_t *wandder_create_etsili_child(wandder_etsili_top_t* top, 
        wandder_generic_body_t * body);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
