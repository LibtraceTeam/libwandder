/*
 *
 * Copyright (c) 2024, 2025 SearchLight Ltd, New Zealand.
 * All rights reserved.
 *
 * This file is part of libwandder.
 *
 * Libwandder was originally developed by the University of Waikato WAND
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
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <math.h>
#include "wandder_internal.h"
#include "libwandder_etsili.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#if defined(__APPLE__)
// Mac OS X / Darwin features
#include <libkern/OSByteOrder.h>
#define bswap_32(x) OSSwapInt32(x)
#define bswap_64(x) OSSwapInt64(x)
#else
#include <byteswap.h>
#endif

#define INITIAL_ENCODER_SIZE 2048
#define INCREMENT_ENCODER_SIZE 512

const uint8_t etsi_lipsdomainid[8] = {
        0x00, 0x04, 0x00, 0x02, 0x02, 0x05, 0x01, 0x11};

const uint8_t wandder_etsi_ipccoid[4] = {0x05, 0x03, 0x0a, 0x02};
const uint8_t wandder_etsi_ipirioid[4] = {0x05, 0x03, 0x0a, 0x01};
const uint8_t wandder_etsi_ipmmccoid[4] = {0x05, 0x05, 0x06, 0x02};
const uint8_t wandder_etsi_ipmmirioid[4] = {0x05, 0x05, 0x06, 0x01};
const uint8_t wandder_etsi_umtsirioid[9] =
        {0x00, 0x04, 0x00, 0x02, 0x02, 0x04, 0x01, 0x0f, 0x05};
const uint8_t wandder_etsi_epsirioid[9] =
        {0x00, 0x04, 0x00, 0x02, 0x02, 0x04, 0x08, 0x11, 0x00};
const uint8_t wandder_etsi_epsccoid[9] =
        {0x00, 0x04, 0x00, 0x02, 0x02, 0x04, 0x09, 0x11, 0x00};

static void init_dumpers(wandder_etsispec_t *dec);
static void free_dumpers(wandder_etsispec_t *dec);
static char *interpret_enum(wandder_etsispec_t *etsidec, wandder_item_t *item,
        wandder_dumper_t *curr, char *valstr, int len);
static const char *stringify_ipaddress(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len);
static char *stringify_3gimei(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len);
static char *stringify_3gcause(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len);
static char *stringify_domain_name(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len);
static char *stringify_bytes_as_hex(wandder_etsispec_t *etsidec,
        wandder_item_t *item, char *valstr, int len);
static char *stringify_tai(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len);
static char *stringify_cgi(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len);
static char *stringify_ecgi(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len);
static char *stringify_sai(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len);
static char *stringify_uli(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len);
static char *stringify_eps_attach_type(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len);
static char *stringify_eps_rat_type(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len);
static char *stringify_eps_cause(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len);
static char *stringify_eps_pdntype(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len);
static char *stringify_eps_ambr(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len);
static char *decrypt_encrypted_payload_item(wandder_etsispec_t *etsidec,
        wandder_item_t *item, char *valstr, int len);
static char *stringify_sequenced_primitives(char *sequence_name,
        wandder_decoder_t *dec, char *space, int spacelen, int interpretas);

static int decrypt_encryption_container(wandder_etsispec_t *etsidec,
        wandder_item_t *item);

#define QUICK_DECODE(fail) \
    ret = wandder_decode_next(dec); \
    if (ret <= 0) { \
        return fail; \
    } \
    ident = wandder_get_identifier(dec);


/*
*  hex2bin() - Convert Hex string into a binary array.
*  2 hex characters (2 x 4 bit) are translated to a binary char (8 bit), in the same order
*  Input: hex string
*  Output: binary char array
*
*  NB: memory allocation and freeing memory must be done before calling this routine
*
*  Contributed by Pim van Stam
*/
static unsigned char * hex2bin (char *hexstr, unsigned char *binvalue,
        int hexstr_size) {
    int i, j;
    char ch, value;

    for (i=0; i < (int) hexstr_size/2; i++) {
        value =0;
        for (j=0; j<2; j++) {
            ch = hexstr[i*2+j];
            if (ch >= '0' && ch <= '9')
                value = (value << 4) + (ch - '0');
            else if (ch >= 'A' && ch <= 'F')
                value = (value << 4) + (ch - 'A' + 10);
            else if (ch >= 'a' && ch <= 'f')
                value = (value << 4) + (ch - 'a' + 10);
        }
        binvalue[i] = (unsigned char) value;
    }
    return(binvalue);
}

static uint32_t decode_length_field(uint8_t *lenstart, uint32_t maxrem,
        int *lenlen) {

    uint8_t lenoctets;
    uint8_t byte;
    uint32_t result = 0;
    int i;

    if (maxrem == 0) {
        *lenlen = 0;
        return 0;
    }

    byte = *lenstart;
    if ((byte & 0x80) == 0) {
        /* definite short form */
        *lenlen = 1;
        return (byte & 0x7f);
    }
    lenoctets = (byte & 0x7f);
    if (lenoctets) {
        /* definite long form */
        if (lenoctets > 8) {
            fprintf(stderr, "libwandder cannot decode length fields longer than 8 bytes!\n");
            *lenlen = 0;
            return 0;
        }
        if (lenoctets > maxrem) {
            fprintf(stderr, "libwandder: length field size is larger than the amount of bytes remaining in the current field? (%u vs %u)\n", lenoctets, maxrem);
            *lenlen = 0;
            return 0;
        }
        *lenlen = lenoctets + 1;
        for (i = 0; i < (int)lenoctets; i++) {
            byte = *(lenstart + i + 1);
            result = result << 8;
            result |= (byte);
        }
    } else {
        /* indefinite form */
        *lenlen = 1;
        result = 0xFFFFFFFF;
    }

    return result;
}

static inline int decrypt_length_sanity_check(uint8_t *data, uint64_t dlen) {

    uint64_t obslen = 0, headerlen = 0, gap = 0;
    int blen, i;

    if (dlen < 2) {
        return 0;
    }

    /* single byte length field */
    if (data[1] < 0x80) {
        obslen = data[1];
        headerlen += 2;  /* 1 byte for identifier, 1 for length */
    } else {
        blen = (data[1] & 0x7f);
        if (blen == 0 || blen > 8) {
            return 0;
        }

        if (dlen <= 2 + blen) {
            return 0;
        }

        for (i = 0; i < blen; i ++) {
            obslen += (data[2 + i] << ( 8 * (blen - (i + 1)) ) );
        }
        headerlen += (2 + blen);
    }

    if (obslen + headerlen > dlen) {
        return 0;
    }

    /* dlen will be increased to the nearest multiple of 16 because of
     * padding at encryption time.
     */
    if (dlen - (obslen + headerlen) > 16) {
        return 0;
    }

    if ((obslen + headerlen) % 16 == 0) {
        gap = 0;
    } else {
        gap = 16 - ((obslen + headerlen) % 16);
    }

    if (dlen - (obslen + headerlen) != gap) {
        return 0;
    }

    return 1;

}

static void wandder_etsili_free_stack(wandder_etsi_stack_t *stack) {
    free(stack->stk);
    free(stack->atthislevel);
    free(stack);
}

wandder_etsispec_t *wandder_create_etsili_decoder(void) {
    wandder_etsispec_t *etsidec = (wandder_etsispec_t *)malloc(
            sizeof(wandder_etsispec_t));

    init_dumpers(etsidec);

    etsidec->stack = NULL;
    etsidec->decstate = 0;
    etsidec->ccformat = 0;
    etsidec->dec = NULL;
    etsidec->encrypt_method = WANDDER_ENCRYPTION_TYPE_NOT_STATED;
    etsidec->decrypt_dec = NULL;
    etsidec->decrypted = NULL;
    etsidec->decrypt_size = 0;
    etsidec->decrypt_stack = NULL;
    etsidec->saved_decrypted_payload = NULL;
    etsidec->saved_payload_size = 0;
    etsidec->saved_payload_name = NULL;
    etsidec->decryption_key = NULL;

    return etsidec;
}

uint8_t wandder_etsili_get_cc_format(wandder_etsispec_t *etsidec) {
    return etsidec->ccformat;
}

static uint8_t wandder_etsili_get_ipmmcc_format(wandder_etsispec_t *etsidec,
        wandder_decoder_t *dec, wandder_dumper_t *startpoint) {
    wandder_found_t *found = NULL;
    wandder_target_t tgt;
    uint8_t *vp = NULL;

    if (etsidec->decstate == 0) {
        fprintf(stderr, "No buffer attached to this decoder -- please call"
                "wandder_attach_etsili_buffer() first!\n");
        return 0;
    }

    /* We already know the format from earlier decoding work, so just use
     * that. This should be the most common case...
     */
    if (etsidec->ccformat != 0) {
        return etsidec->ccformat;
    }

    wandder_reset_decoder(dec);
    tgt.parent = &etsidec->ipmmcc;
    tgt.itemid = 2;
    tgt.found = false;

    if (wandder_search_items(dec, 0, startpoint, &tgt, 1, &found, 1) > 0) {
        int64_t val;
        uint32_t len;

        len = found->list[0].item->length;
        vp = found->list[0].item->valptr;
        if (found->list[0].targetid == 0) {
            val = wandder_decode_integer_value(vp, len);
            switch(val) {
                case 0:
                    etsidec->ccformat = WANDDER_ETSILI_CC_FORMAT_IP;
                    break;
                case 1:
                    etsidec->ccformat = WANDDER_ETSILI_CC_FORMAT_UDP;
                    break;
                case 2:
                case 5:
                    etsidec->ccformat = WANDDER_ETSILI_CC_FORMAT_RTP;
                    break;
                case 4:
                    etsidec->ccformat = WANDDER_ETSILI_CC_FORMAT_TCP;
                    break;
                /* TODO one day we might care about MSRP or UDPTL */
                default:
                    etsidec->ccformat = WANDDER_ETSILI_CC_FORMAT_UNKNOWN;
            }

        }
        wandder_free_found(found);
    }

    return etsidec->ccformat;
}

static uint8_t wandder_etsili_get_email_format(wandder_etsispec_t *etsidec,
        wandder_decoder_t *dec, wandder_dumper_t *startpoint) {
    wandder_found_t *found = NULL;
    wandder_target_t tgt;
    uint8_t *vp = NULL;

    if (etsidec->decstate == 0) {
        fprintf(stderr, "No buffer attached to this decoder -- please call"
                "wandder_attach_etsili_buffer() first!\n");
        return 0;
    }

    /* We already know the format from earlier decoding work, so just use
     * that. This should be the most common case...
     */
    if (etsidec->ccformat != 0) {
        return etsidec->ccformat;
    }

    /* Find the email-Format field in the encoded record, if present */
    wandder_reset_decoder(dec);
    tgt.parent = &etsidec->emailcc;
    tgt.itemid = 1;
    tgt.found = false;

    if (wandder_search_items(dec, 0, startpoint, &tgt, 1, &found, 1) > 0) {
        int64_t val;
        uint32_t len;

        len = found->list[0].item->length;
        vp = found->list[0].item->valptr;

        if (found->list[0].targetid == 0) {
            val = wandder_decode_integer_value(vp, len);
            if (val <= 255) {
                etsidec->ccformat = (uint8_t) val;
            }
        }
        wandder_free_found(found);
    }

    return etsidec->ccformat;
}

void wandder_free_etsili_decoder(wandder_etsispec_t *etsidec) {

    if (!etsidec) {
        return;
    }

    free_dumpers(etsidec);

    if (etsidec->stack) {
        wandder_etsili_free_stack(etsidec->stack);
    }
    if (etsidec->decrypt_stack) {
        wandder_etsili_free_stack(etsidec->decrypt_stack);
    }
    if (etsidec->decstate) {
        free_wandder_decoder(etsidec->dec);
    }
    if (etsidec->decrypt_dec) {
        free_wandder_decoder(etsidec->decrypt_dec);
    }
    if (etsidec->saved_decrypted_payload) {
        free(etsidec->saved_decrypted_payload);
    }
    if (etsidec->decrypted) {
        free(etsidec->decrypted);
    }
    if (etsidec->decryption_key) {
        free(etsidec->decryption_key);
    }
    free(etsidec);
}

void wandder_attach_etsili_buffer(wandder_etsispec_t *etsidec,
        uint8_t *source, uint32_t len, bool copy) {

    etsidec->dec = init_wandder_decoder(etsidec->dec, source, len, copy);
    etsidec->decstate = 1;
}

wandder_dumper_t *wandder_get_etsili_structure(wandder_etsispec_t *etsidec) {
    return &(etsidec->root);
}

struct timeval wandder_etsili_get_header_timestamp(wandder_etsispec_t *etsidec) 
{
    struct timeval tv;
    uint32_t ident;
    int ret;
    wandder_decoder_t *dec = etsidec->dec;

    tv.tv_sec = 0;
    tv.tv_usec = 0;
    if (etsidec->decstate == 0) {
        fprintf(stderr, "No buffer attached to this decoder -- please call"
                "wandder_attach_etsili_buffer() first!\n");
        return tv;
    }

    /* Find PSHeader */
    wandder_reset_decoder(dec);
    QUICK_DECODE(tv);
    QUICK_DECODE(tv);

    /* dec->current should be pointing right at PSHeader */
    if (ident != 1) {
        return tv;
    }

    if ((ret = wandder_decode_sequence_until(dec, 5)) < 0) {
        return tv;
    }

    if (ret == 1) {
        tv = wandder_generalizedts_to_timeval(dec,
                (char *)(wandder_get_itemptr(dec)),
                wandder_get_itemlen(dec));
        return tv;
    } else if ((ret = wandder_decode_sequence_until(etsidec->dec, 7)) < 0) {
        return tv;
    }

    if (ret == 1) {
        QUICK_DECODE(tv);
        tv.tv_sec = wandder_get_integer_value(dec->current, NULL);
        QUICK_DECODE(tv);
        tv.tv_usec = wandder_get_integer_value(dec->current, NULL);
        return tv;
    }
    return tv;

}

uint32_t wandder_etsili_get_pdu_length(wandder_etsispec_t *etsidec) {

    if (etsidec->decstate == 0) {
        fprintf(stderr, "No buffer attached to this decoder -- please call"
                "wandder_attach_etsili_buffer() first!\n");
        return 0;
    }
    /* Easy, reset the decoder then grab the length of the first element 
    (provided it is not indefinite)*/
    wandder_reset_decoder(etsidec->dec);

    if (wandder_decode_next(etsidec->dec) <= 0) {
        return 0;
    }

    int preamble = etsidec->dec->current->preamblelen;
    /* Don't forget to include the preamble length so the caller can skip
     * over the entire PDU if desired.
     */
    if (etsidec->dec->current->indefform){
        return wandder_decode_skip(etsidec->dec);
    }
    else {
        return wandder_get_itemlen(etsidec->dec) + preamble;
    }
}

int wandder_set_etsili_decryption_key(wandder_etsispec_t *etsidec, char *key) {

    if (etsidec->decryption_key) {
        free(etsidec->decryption_key);
    }
    etsidec->decryption_key = strdup(key);
    return 1;
}

static inline void push_stack(wandder_etsi_stack_t *stack,
        wandder_dumper_t *next) {

    stack->current ++;

    if (stack->current == stack->alloced) {
        stack->stk = (wandder_dumper_t **)realloc(stack->stk,
                sizeof(wandder_dumper_t *) * (stack->current + 10));
        stack->atthislevel = (int *)realloc(stack->atthislevel,
                sizeof(int) * (stack->current + 10));

        stack->alloced += 10;
    }

    stack->atthislevel[stack->current] = 0;
    stack->stk[stack->current] = next;

}

/* Most of the code for this function is derived from example code provided
 * by Pim van Stam.
 */
static int decrypt_payload_content_aes_192_cbc(uint8_t *ciphertext,
        int ciphertext_len,
        char *key_hex, int32_t seqno, unsigned char *plainspace, int plainlen) {

    EVP_CIPHER_CTX *ctx;
    int32_t swap_seqno = htonl(seqno);
    uint8_t iv[16];
    int i, key_hex_size;
    uint8_t *key_bin;
    int finallen = 0, interimlen = 0;

    assert(sizeof(int32_t) == 4);

    if (key_hex == NULL) {
        fprintf(stderr, "Unable to decrypt payload content as no encryption key has been provided.\nUse LIBWANDDER_ETSILI_DECRYPTION_KEY environment variable or\nwandder_set_etsili_decryption_key() function to provide the key.\n");
        return -1;
    }

    for (i = 0; i < 4; i++) {
        memcpy(&(iv[i * sizeof(int32_t)]), &swap_seqno, sizeof(int32_t));
    }

    key_hex_size = strlen(key_hex);
    key_bin = calloc(1, key_hex_size);     // twice as much as we need

    hex2bin(key_hex, key_bin, key_hex_size);

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Unable to create EVP context for decryption: %s\n",
                strerror(errno));
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key_bin, iv) != 1) {
        fprintf(stderr, "Unable to initialise EVP context for decryption: %s\n",
                strerror(errno));
        return -1;
    }

    /* Disable padding because the ciphertext should already be a multiple
     * of the block size.
     */
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (EVP_DecryptUpdate(ctx, plainspace, &interimlen, ciphertext,
            ciphertext_len) != 1) {
        fprintf(stderr, "Error while decrypting CC payload content: %s\n",
                strerror(errno));
        return -1;
    }
    finallen = interimlen;

    if (EVP_DecryptFinal_ex(ctx, plainspace + finallen, &interimlen) != 1) {
        fprintf(stderr, "Error while finishing decryption of CC payload: %s\n",
                strerror(errno));
        return -1;
    }

    finallen += interimlen;
    EVP_CIPHER_CTX_free(ctx);
    free(key_bin);

    return finallen;
}

static char *decode_field_to_str(wandder_etsispec_t *etsidec,
        wandder_decoder_t *dec,
        wandder_etsi_stack_t *stack, char *space, int spacelen) {
    uint32_t ident;
    wandder_dumper_t *curr = NULL;
    char valstr[16384];

    if (wandder_decode_next(dec) <= 0) {
        return NULL;
    }

    while (wandder_get_level(dec) < stack->current) {
        assert(stack->current > 0);
        stack->current --;
    }

    curr = stack->stk[stack->current];
    if (curr == NULL) {
        return NULL;
    }

    switch(wandder_get_class(dec)) {

        case WANDDER_CLASS_CONTEXT_PRIMITIVE:
            ident = wandder_get_identifier(dec);
            (etsidec->stack->atthislevel[stack->current])++;

            if (curr == &(etsidec->emailcc) && ident == 1) {
                int64_t val;
                val = wandder_get_integer_value(dec->current, NULL);
                if (val <= 255) {
                    etsidec->ccformat = (uint8_t) val;
                }
            }

            if (curr->members[ident].interpretas == WANDDER_TAG_IPPACKET) {
                if (dec == etsidec->decrypt_dec) {
                    /* cache the decrypted payload content */
                    etsidec->saved_payload_size = dec->current->length;
                    etsidec->saved_payload_name = curr->members[ident].name;
                    if (etsidec->saved_decrypted_payload) {
                        free(etsidec->saved_decrypted_payload);
                    }
                    if (etsidec->ccformat == WANDDER_ETSILI_CC_FORMAT_UNKNOWN) {
                        etsidec->ccformat = WANDDER_ETSILI_CC_FORMAT_IP;
                    }
                    etsidec->saved_decrypted_payload = calloc(1,
                            dec->current->length);
                    memcpy(etsidec->saved_decrypted_payload,
                            dec->current->valptr, dec->current->length);
                }

                /* If we are an IP CC we can stop, but IPMM CCs have to
                 * keep going in case the optional fields are present :(
                 */
                if (strcmp(curr->members[ident].name, "iPPackets") == 0) {
                    return NULL;
                }
                if (strcmp(curr->members[ident].name, "uMTSCC") == 0) {
                    return NULL;
                }
                if (strcmp(curr->members[ident].name, "content") == 0) {
                    return NULL;
                }
                return wandder_etsili_get_next_fieldstr(etsidec, space,
                        spacelen);
            }
            else if (curr->members[ident].interpretas == WANDDER_TAG_BINARY_IP)
            {
                if (stringify_ipaddress(etsidec, dec->current, curr,
                        valstr, 16384) == NULL) {
                    fprintf(stderr, "Failed to interpret IP field %d:%d\n",
                            stack->current, ident);
                    return NULL;
                }
            }

            else if (curr->members[ident].interpretas == WANDDER_TAG_ENUM) {
                if (interpret_enum(etsidec, dec->current, curr,
                            valstr, 16384) == NULL) {
                    fprintf(stderr, "Failed to interpret enum field %d:%d\n",
                            stack->current, ident);
                    return NULL;
                }
            }
            else if (curr->members[ident].interpretas == WANDDER_TAG_3G_IMEI) {
                if (stringify_3gimei(etsidec, dec->current, curr,
                            valstr, 16384) == NULL) {
                    fprintf(stderr,
                            "Failed to interpret 3G IMEI-style field %d:%d\n",
                            stack->current, ident);
                    return NULL;
                }
            }
            else if (curr->members[ident].interpretas ==
                    WANDDER_TAG_3G_SM_CAUSE) {
                if (stringify_3gcause(etsidec, dec->current, curr,
                            valstr, 16384) == NULL) {
                    fprintf(stderr,
                            "Failed to interpret 3G SM-Cause field %d:%d\n",
                            stack->current, ident);
                    return NULL;
                }
            }
            else if (curr->members[ident].interpretas == WANDDER_TAG_DOMAIN_NAME) {
                if (stringify_domain_name(etsidec, dec->current, curr,
                            valstr, 16384) == NULL) {
                    fprintf(stderr,
                            "Failed to interpret domain name field %d:%d\n",
                            stack->current, ident);
                    return NULL;
                }
            }
            else if (curr->members[ident].interpretas == WANDDER_TAG_HEX_BYTES) {
                if (stringify_bytes_as_hex(etsidec, dec->current,
                            valstr, 16384) == NULL) {
                    fprintf(stderr,
                            "Failed to interpret hex bytes field %d:%d\n",
                            stack->current, ident);
                    return NULL;
                }
            }
            else if (curr->members[ident].interpretas == WANDDER_TAG_TAI) {
                if (stringify_tai(etsidec, dec->current, curr,
                            valstr, 16384) == NULL) {
                    fprintf(stderr,
                            "Failed to interpret TAI field %d:%d\n",
                            stack->current, ident);
                    return NULL;
                }
            }
            else if (curr->members[ident].interpretas == WANDDER_TAG_ECGI) {
                if (stringify_ecgi(etsidec, dec->current, curr,
                            valstr, 16384) == NULL) {
                    fprintf(stderr,
                            "Failed to interpret ECGI field %d:%d\n",
                            stack->current, ident);
                    return NULL;
                }
            }
            else if (curr->members[ident].interpretas == WANDDER_TAG_CGI) {
                if (stringify_cgi(etsidec, dec->current, curr,
                            valstr, 16384) == NULL) {
                    fprintf(stderr,
                            "Failed to interpret CGI field %d:%d\n",
                            stack->current, ident);
                    return NULL;
                }
            }
            else if (curr->members[ident].interpretas == WANDDER_TAG_SAI) {
                if (stringify_sai(etsidec, dec->current, curr,
                            valstr, 16384) == NULL) {
                    fprintf(stderr,
                            "Failed to interpret SAI field %d:%d\n",
                            stack->current, ident);
                    return NULL;
                }
            }
            else if (curr->members[ident].interpretas == WANDDER_TAG_ULI) {
                if (stringify_uli(etsidec, dec->current, curr,
                            valstr, 16384) == NULL) {
                    fprintf(stderr,
                            "Failed to interpret ULI field %d:%d\n",
                            stack->current, ident);
                    return NULL;
                }
            }
            else if (curr->members[ident].interpretas ==
                    WANDDER_TAG_EPS_APN_AMBR) {
                if (stringify_eps_ambr(etsidec, dec->current, curr,
                            valstr, 16384) == NULL) {
                    fprintf(stderr,
                            "Failed to interpret EPS APN-AMBR field: %d:%d\n",
                            stack->current, ident);
                    return NULL;
                }
            }
            else if (curr->members[ident].interpretas ==
                    WANDDER_TAG_EPS_CAUSE) {
                if (stringify_eps_cause(etsidec, dec->current, curr,
                            valstr, 16384) == NULL) {
                    fprintf(stderr,
                            "Failed to interpret EPS Cause field: %d:%d\n",
                            stack->current, ident);
                    return NULL;
                }
            }
            else if (curr->members[ident].interpretas ==
                    WANDDER_TAG_EPS_PDN_TYPE) {
                if (stringify_eps_pdntype(etsidec, dec->current, curr,
                            valstr, 16384) == NULL) {
                    fprintf(stderr,
                            "Failed to interpret EPS PDN Type field: %d:%d\n",
                            stack->current, ident);
                    return NULL;
                }
            }
            else if (curr->members[ident].interpretas ==
                    WANDDER_TAG_EPS_ATTACH_TYPE) {
                if (stringify_eps_attach_type(etsidec, dec->current, curr,
                            valstr, 16384) == NULL) {
                    fprintf(stderr,
                            "Failed to interpret EPS Attach Type field: %d:%d\n",
                            stack->current, ident);
                    return NULL;
                }
            }
            else if (curr->members[ident].interpretas ==
                    WANDDER_TAG_EPS_RAT_TYPE) {
                if (stringify_eps_rat_type(etsidec, dec->current, curr,
                            valstr, 16384) == NULL) {
                    fprintf(stderr,
                            "Failed to interpret EPS RAT Type field: %d:%d\n",
                            stack->current, ident);
                    return NULL;
                }
            }
            else if (curr->members[ident].interpretas ==
                    WANDDER_TAG_ENCRYPTED) {
                assert(etsidec->decrypted == NULL);
                if (decrypt_encrypted_payload_item(etsidec,
                        dec->current, valstr, 16384) == NULL) {
                    /* Decryption was successful -- go ahead with
                     * processing the decrypted data... */

                    return wandder_etsili_get_next_fieldstr(etsidec, space,
                            spacelen);
                }

                /* Otherwise, we will have fallen back to just a hex
                 * dump of the encrypted data so we can return that inside
                 * 'space'.
                 */
            }
            else {
                if (!wandder_get_valuestr(dec->current, valstr, 16384,
                        curr->members[ident].interpretas)) {
                    fprintf(stderr, "Failed to interpret field %d:%d\n",
                            stack->current, ident);
                    return NULL;
                }
            }

            snprintf(space, spacelen, "%s: %s", curr->members[ident].name,
                    valstr);
            break;

        case WANDDER_CLASS_UNIVERSAL_PRIMITIVE:
            ident = (uint32_t)stack->atthislevel[stack->current];
            (stack->atthislevel[stack->current])++;
            if (!wandder_get_valuestr(dec->current, valstr, 16384,
                    wandder_get_identifier(dec))) {
                fprintf(stderr, "Failed to interpret standard field %d:%d\n",
                        stack->current, ident);
                return NULL;
            }
            snprintf(space, spacelen, "%s: %s", curr->members[ident].name,
                    valstr);
            break;

        case WANDDER_CLASS_UNIVERSAL_CONSTRUCT:
            if (curr == NULL) {
                return NULL;
            }
            snprintf(space, spacelen, "%s:", curr->sequence.name);
            (stack->atthislevel[stack->current])++;
            push_stack(stack, curr->sequence.descend);
            break;

        case WANDDER_CLASS_CONTEXT_CONSTRUCT:
            if (curr == NULL) {
                return NULL;
            }
            ident = wandder_get_identifier(dec);
            if (curr->members[ident].descend) {
                (stack->atthislevel[stack->current])++;
                snprintf(space, spacelen, "%s:", curr->members[ident].name);
                push_stack(stack, curr->members[ident].descend);
            } else {
                if (stringify_sequenced_primitives(curr->members[ident].name,
                        dec, space, spacelen,
                        curr->members[ident].interpretas) == NULL) {
                    return NULL;
                }
                wandder_decode_skip(dec);
            }
            break;
        default:
            return NULL;
    }
    return space;
}

char *wandder_etsili_get_next_fieldstr(wandder_etsispec_t *etsidec, char *space,
        int spacelen) {

    if (etsidec->decstate == 0) {
        fprintf(stderr, "No buffer attached to this decoder -- please call"
                "wandder_attach_etsili_buffer() first!\n");
        return NULL;
    }

    if (etsidec->stack == NULL) {
        etsidec->stack = (wandder_etsi_stack_t *)malloc(
                sizeof(wandder_etsi_stack_t));
        etsidec->stack->stk = (wandder_dumper_t **)malloc(
                sizeof(wandder_dumper_t *) * 10);
        etsidec->stack->atthislevel = (int *)malloc(sizeof(int *) * 10);

        etsidec->stack->alloced = 10;
        etsidec->stack->stk[0] = &etsidec->root;
        etsidec->stack->current = 0;
        etsidec->stack->atthislevel[0] = 0;
    }

    if (etsidec->decrypted) {
        if (etsidec->decrypt_stack == NULL) {
            etsidec->decrypt_stack = (wandder_etsi_stack_t *)malloc(
                    sizeof(wandder_etsi_stack_t));
            etsidec->decrypt_stack->stk = (wandder_dumper_t **)malloc(
                    sizeof(wandder_dumper_t *) * 10);
            etsidec->decrypt_stack->atthislevel = (int *)malloc(sizeof(int *) * 10);

            etsidec->decrypt_stack->alloced = 10;
            etsidec->decrypt_stack->stk[0] = &etsidec->encryptedpayloadroot;
            etsidec->decrypt_stack->current = 0;
            etsidec->decrypt_stack->atthislevel[0] = 0;
        }

        if (decode_field_to_str(etsidec, etsidec->decrypt_dec,
                etsidec->decrypt_stack, space, spacelen) == NULL) {

            /* we either failed or we ran out of decrypted content... */
            free(etsidec->decrypted);
            etsidec->decrypted = NULL;
            return wandder_etsili_get_next_fieldstr(etsidec, space, spacelen);
        }
        return space;
    }

    return decode_field_to_str(etsidec, etsidec->dec, etsidec->stack, space,
            spacelen);
}

wandder_decoder_t *wandder_get_etsili_base_decoder(wandder_etsispec_t *dec) {
    return (dec->dec);
}

int wandder_etsili_get_nesting_level(wandder_etsispec_t *dec) {
    if (dec->decrypted) {
        return wandder_get_level(dec->decrypt_dec) +
                wandder_get_level(dec->dec);
    }
    return wandder_get_level(dec->dec);
}

static uint8_t *internal_get_cc_contents(wandder_etsispec_t *etsidec,
        wandder_decoder_t *dec, uint32_t *len, char *name, int namelen) {

    uint8_t *vp = NULL;
    int tgtcount;
    wandder_found_t *found = NULL;
    wandder_target_t cctgts[6];
    wandder_dumper_t *startpoint;

    if (etsidec->decstate == 0) {
        fprintf(stderr, "No buffer attached to this decoder -- please call"
                "wandder_attach_etsili_buffer() first!\n");
        return NULL;
    }
    etsidec->ccformat = WANDDER_ETSILI_CC_FORMAT_UNKNOWN;

    /* Find IPCCContents or IPMMCCContents or UMTSCC or emailCC or epsCC */
    cctgts[0].parent = &etsidec->ipcccontents;
    cctgts[0].itemid = 0;
    cctgts[0].found = false;

    cctgts[1].parent = &etsidec->ipmmcc;
    cctgts[1].itemid = 1;
    cctgts[1].found = false;

    cctgts[2].parent = &etsidec->cccontents;
    cctgts[2].itemid = 4;
    cctgts[2].found = false;

    cctgts[3].parent = &etsidec->emailcc;
    cctgts[3].itemid = 2;
    cctgts[3].found = false;

    cctgts[4].parent = &etsidec->epscc;
    cctgts[4].itemid = 2;
    cctgts[4].found = false;

    if (dec == etsidec->dec) {
        /* Also look for encrypted payload */
        tgtcount = 6;
        cctgts[5].parent = &etsidec->payload;
        cctgts[5].itemid = 4;
        cctgts[5].found = false;
        startpoint = &(etsidec->root);
    } else if (dec == etsidec->decrypt_dec) {
        tgtcount = 5;
        startpoint = &(etsidec->encryptedpayloadroot);
    } else {
        tgtcount = 5;
        startpoint = &(etsidec->root);
    }

    wandder_reset_decoder(dec);
    *len = 0;
    if (wandder_search_items(dec, 0, startpoint, cctgts,
                tgtcount, &found, 1) > 0) {
        *len = found->list[0].item->length;
        vp = found->list[0].item->valptr;

        if (found->list[0].targetid == 0) {
            strncpy(name, etsidec->ipcccontents.members[0].name, namelen);
            etsidec->ccformat = WANDDER_ETSILI_CC_FORMAT_IP;
        } else if (found->list[0].targetid == 1) {
            strncpy(name, etsidec->ipmmcc.members[1].name, namelen);
            wandder_etsili_get_ipmmcc_format(etsidec, dec, startpoint);
        } else if (found->list[0].targetid == 2) {
            strncpy(name, etsidec->cccontents.members[4].name, namelen);
            etsidec->ccformat = WANDDER_ETSILI_CC_FORMAT_IP;
        } else if (found->list[0].targetid == 3) {
            strncpy(name, etsidec->emailcc.members[2].name, namelen);
            wandder_etsili_get_email_format(etsidec, dec, startpoint);
        } else if (found->list[0].targetid == 4) {
            strncpy(name, etsidec->epscc.members[2].name, namelen);
            etsidec->ccformat = WANDDER_ETSILI_CC_FORMAT_IP;
        } else if (found->list[0].targetid == 5) {
            if (decrypt_encryption_container(etsidec, found->list[0].item)) {
                return internal_get_cc_contents(etsidec, etsidec->decrypt_dec,
                        len, name, namelen);
            }
        }
        wandder_free_found(found);
    }

    return vp;
}

uint8_t *wandder_etsili_get_cc_contents(wandder_etsispec_t *etsidec,
        uint32_t *len, char *name, int namelen) {

    if (etsidec->decstate == 0) {
        fprintf(stderr, "No buffer attached to this decoder -- please call"
                "wandder_attach_etsili_buffer() first!\n");
        return NULL;
    }

    /* If our payload is encrypted, maybe we've already decrypted it
     * and cached the content to save time? */
    if (etsidec->saved_decrypted_payload) {
        assert(etsidec->saved_payload_name != NULL);
        if (strcmp(etsidec->saved_payload_name, "sIPContent") == 0) {
            return NULL;
        }
        if (strcmp(etsidec->saved_payload_name, "originalIPMMMessage") == 0) {
            return NULL;
        }
        if (strcmp(etsidec->saved_payload_name, "h323Message") == 0) {
            return NULL;
        }
        strncpy(name, etsidec->saved_payload_name, namelen);
        *len = etsidec->saved_payload_size;
        return etsidec->saved_decrypted_payload;
    }

    return internal_get_cc_contents(etsidec, etsidec->dec, len, name, namelen);

}

uint8_t *wandder_etsili_get_encryption_container(
        wandder_etsispec_t *etsidec, wandder_decoder_t *dec, uint32_t *len) {

    wandder_found_t *found = NULL;
    wandder_target_t target;
    uint8_t *vp = NULL;

    wandder_reset_decoder(dec);
    target.parent = &etsidec->payload;
    target.itemid = 4;
    target.found = false;

    *len = 0;

    if (wandder_search_items(dec, 0, &(etsidec->root), &target, 1,
                &found, 1) > 0) {
        *len = found->list[0].item->length;
        vp = found->list[0].item->valptr;

        wandder_free_found(found);
    }
    return vp;

}

uint8_t *wandder_etsili_get_integrity_check_contents(
        wandder_etsispec_t *etsidec, wandder_decoder_t *dec, uint32_t *len) {

    wandder_found_t *found = NULL;
    wandder_target_t target;
    uint8_t *vp = NULL;

    wandder_reset_decoder(dec);
    target.parent = &etsidec->tripayload;
    target.itemid = 0;
    target.found = false;

    *len = 0;

    if (wandder_search_items(dec, 0, &(etsidec->root), &target, 1,
                &found, 1) > 0) {
        *len = found->list[0].item->length;
        vp = found->list[0].item->valptr;

        wandder_free_found(found);
    }
    return vp;
}

static uint8_t *internal_get_iri_contents(wandder_etsispec_t *etsidec,
        wandder_decoder_t *dec, uint32_t *len, uint8_t *ident,
        char *name, int namelen) {

    uint8_t *vp = NULL;
    wandder_found_t *found = NULL;
    wandder_target_t iritgts[4];
    wandder_dumper_t *startpoint;
    int tgtcount = 4;

    if (dec == etsidec->decrypt_dec) {
        startpoint = &(etsidec->encryptedpayloadroot);
        tgtcount = 3;
    } else {
        startpoint = &(etsidec->root);
    }

    wandder_reset_decoder(dec);
    /* originalIPMMMessage */
    iritgts[0].parent = &etsidec->ipmmiricontents;
    iritgts[0].itemid = 0;
    iritgts[0].found = false;

    /* sIPContents */
    iritgts[1].parent = &etsidec->sipmessage;
    iritgts[1].itemid = 2;
    iritgts[1].found = false;

    /* rawAAAData */
    iritgts[2].parent = &etsidec->ipiricontents;
    iritgts[2].itemid = 15;
    iritgts[2].found = false;

    /* encryptedContainer */
    iritgts[3].parent = &etsidec->payload;
    iritgts[3].itemid = 4;
    iritgts[3].found = false;

    /* TODO H323 contents... */

    *len = 0;
    if (wandder_search_items(dec, 0, startpoint, iritgts, tgtcount,
                &found, 1) > 0) {
        *len = found->list[0].item->length;
        vp = found->list[0].item->valptr;

        if (found->list[0].targetid == 0) {
            strncpy(name, etsidec->ipmmiricontents.members[0].name, namelen);
            *ident = WANDDER_IRI_CONTENT_IP;
        } else if (found->list[0].targetid == 1) {
            strncpy(name, etsidec->sipmessage.members[2].name, namelen);
            *ident = WANDDER_IRI_CONTENT_SIP;
        } else if (found->list[0].targetid == 2) {
            strncpy(name, etsidec->ipiricontents.members[15].name, namelen);
            *ident = WANDDER_IRI_CONTENT_IP;   // right?
        } else if (found->list[0].targetid == 3) {
            if (decrypt_encryption_container(etsidec, found->list[0].item)) {
                return internal_get_iri_contents(etsidec, etsidec->decrypt_dec,
                        len, ident, name, namelen);
            }
        }
        wandder_free_found(found);
    }
    return vp;
}

uint8_t *wandder_etsili_get_iri_contents(wandder_etsispec_t *etsidec,
        uint32_t *len, uint8_t *ident, char *name, int namelen) {


    if (etsidec->decstate == 0) {
        fprintf(stderr, "No buffer attached to this decoder -- please call"
                "wandder_attach_etsili_buffer() first!\n");
        return NULL;
    }
    if (etsidec->saved_decrypted_payload) {
        assert(etsidec->saved_payload_name != NULL);
        if (strcmp(etsidec->saved_payload_name, "sIPContent") == 0) {
            strncpy(name, etsidec->saved_payload_name, namelen);
            *len = etsidec->saved_payload_size;
            *ident = WANDDER_IRI_CONTENT_SIP;
            return etsidec->saved_decrypted_payload;
        } else if (strcmp(etsidec->saved_payload_name,
                "originalIPMMMessage") == 0) {
            strncpy(name, etsidec->saved_payload_name, namelen);
            *len = etsidec->saved_payload_size;
            *ident = WANDDER_IRI_CONTENT_IP;
            return etsidec->saved_decrypted_payload;
        } else if (strcmp(etsidec->saved_payload_name,
                "h323Message") == 0) {
            strncpy(name, etsidec->saved_payload_name, namelen);
            *len = etsidec->saved_payload_size;
            *ident = WANDDER_IRI_CONTENT_IP;
            return etsidec->saved_decrypted_payload;
        } else {
            return NULL;
        }
    }

    return internal_get_iri_contents(etsidec, etsidec->dec, len, ident,
            name, namelen);
}

uint32_t wandder_etsili_get_cin(wandder_etsispec_t *etsidec) {

    uint32_t ident;
    int ret;
    wandder_decoder_t *dec = etsidec->dec;

    if (etsidec->decstate == 0) {
        fprintf(stderr, "No buffer attached to this decoder -- please call"
                "wandder_attach_etsili_buffer() first!\n");
        return 0;
    }

    wandder_reset_decoder(etsidec->dec);
    QUICK_DECODE(0);
    QUICK_DECODE(0);
    if (ident != 1) {
        return 0;
    }

    /* Work our way to the communicationIdentifier sequence */
    do {
        QUICK_DECODE(0);
    } while (ident < 3);

    if (ident != 3) {
        return 0;
    }

    /* Skip past the contents of the NetworkIdentifier field */
    QUICK_DECODE(0);
    if (ident == 0) {
        wandder_decode_skip(etsidec->dec);
    }

    /* Get communicationIdentityNumber if present */
    do {
        QUICK_DECODE(0);
    } while (ident < 1);

    if (ident != 1) {
        return 0;
    }

    return (uint32_t)(wandder_get_integer_value(etsidec->dec->current, NULL));

}

char *wandder_etsili_get_liid(wandder_etsispec_t *etsidec, char *space,
        int spacelen) {

    uint32_t ident;
    int ret;
    wandder_decoder_t *dec = etsidec->dec;

    if (etsidec->decstate == 0) {
        fprintf(stderr, "No buffer attached to this decoder -- please call"
                "wandder_attach_etsili_buffer() first!\n");
        return NULL;
    }

    wandder_reset_decoder(etsidec->dec);
    QUICK_DECODE(NULL);
    QUICK_DECODE(NULL);
    if (ident != 1) {
        return NULL;
    }

    do {
        QUICK_DECODE(NULL);
    } while (ident < 1);

    if (ident != 1) {
        return NULL;
    }

    if (wandder_get_valuestr(etsidec->dec->current, space, (uint16_t)spacelen,
            WANDDER_TAG_OCTETSTRING) == NULL) {
        return NULL;
    }
    return space;
}

static inline int _wandder_etsili_is_ka(wandder_etsispec_t *etsidec,
        uint8_t isresp) {

    int ret = -1;
    uint32_t ident;
    wandder_decoder_t *dec = etsidec->dec;

    if (etsidec->decstate == 0) {
        fprintf(stderr, "No buffer attached to this decoder -- please call"
                "wandder_attach_etsili_buffer() first!\n");
        return -1;
    }

    /* Manual decode tends to be a lot faster than using the search
     * method, especially when we know exactly what we're searching for
     * and what we can skip entirely.
     */

    wandder_reset_decoder(etsidec->dec);
    QUICK_DECODE(-1);
    QUICK_DECODE(-1);
    if (ident == 1) {
        /* Skip pSHeader */
        wandder_decode_skip(etsidec->dec);
        QUICK_DECODE(-1);
    }

    if (ident != 2) {
        return 0;
    }

    QUICK_DECODE(-1);
    if (ident != 2) {
        return 0;
    }

    QUICK_DECODE(-1);
    if (!isresp && ident != 3) {
        return 0;
    }
    if (isresp && ident != 4) {
        return 0;
    }
    return 1;
}

int wandder_etsili_is_keepalive(wandder_etsispec_t *etsidec) {
    return _wandder_etsili_is_ka(etsidec, 0);
}

int wandder_etsili_is_keepalive_response(wandder_etsispec_t *etsidec) {

    return _wandder_etsili_is_ka(etsidec, 1);
}

static inline int64_t decode_sequence_number(wandder_decoder_t *dec) {

    uint32_t ident;
    int64_t res;
    int ret;

    wandder_reset_decoder(dec);
    QUICK_DECODE(-1);
    QUICK_DECODE(-1);
    if (ident != 1) {
        return -1;
    }

    do {
        QUICK_DECODE(-1);
        if (wandder_get_class(dec) == WANDDER_CLASS_CONTEXT_CONSTRUCT
                || wandder_get_class(dec) == WANDDER_CLASS_UNIVERSAL_CONSTRUCT)
        {
            wandder_decode_skip(dec);
        }
    } while (ident < 4);

    if (ident != 4) {
        return -1;
    }

    res = wandder_get_integer_value(dec->current, NULL);
    return res;
}

int64_t wandder_etsili_get_sequence_number(wandder_etsispec_t *etsidec) {

    if (etsidec->decstate == 0) {
        fprintf(stderr, "No buffer attached to this decoder -- please call"
                "wandder_attach_etsili_buffer() first!\n");
        return -1;
    }

    return decode_sequence_number(etsidec->dec);
}

static char *stringify_3gcause(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len) {

    uint8_t *ptr = (uint8_t *)item->valptr;

    switch(*ptr) {
        case 36:
            strncpy(valstr, "Regular Deactivation", len);
            break;
        default:
            strncpy(valstr, "Unknown", len);
            break;
    }
    return valstr;
}

static char *stringify_eps_pdntype(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len) {

    uint8_t *ptr = (uint8_t *)item->valptr;

    switch(*ptr) {
        case 1:
            strncpy(valstr, "IPv4", len);
            break;
        case 2:
            strncpy(valstr, "IPv6", len);
            break;
        case 3:
            strncpy(valstr, "IPv4v6", len);
            break;
        case 4:
            strncpy(valstr, "Non-IP", len);
            break;
        case 5:
            strncpy(valstr, "Ethernet", len);
            break;

        default:
            snprintf(valstr, len, "%u", *ptr);
            break;
    }
    return valstr;
}

static char *stringify_eps_cause(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len) {

    uint8_t *ptr = (uint8_t *)item->valptr;

    switch(*ptr) {
        case 13:
            strncpy(valstr, "Network Failure", len);
            break;
        case 16:
            strncpy(valstr, "Request Accepted", len);
            break;
        case 64:
            strncpy(valstr, "Context Not Found", len);
            break;
        case 65:
            strncpy(valstr, "Invalid Message Format", len);
            break;
        case 67:
            strncpy(valstr, "Invalid Length", len);
            break;
        case 66:
            strncpy(valstr, "Version not supported by next peer", len);
            break;
        case 72:
            strncpy(valstr, "System Failure", len);
            break;
        case 68:
            strncpy(valstr, "Service not supported", len);
            break;
        case 69:
            strncpy(valstr, "Mandatory IE incorrect", len);
            break;
        case 70:
            strncpy(valstr, "Mandatory IE missing", len);
            break;
        case 94:
            strncpy(valstr, "Request rejected (reason not specified)", len);
            break;
        case 110:
            strncpy(valstr, "Temporarily rejected due to handover procedure in progress", len);
            break;
        default:
            snprintf(valstr, len, "%u", *ptr);
            break;
    }
    return valstr;
}

static char *stringify_eps_ambr(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len) {

    uint32_t *uplink, *downlink;

    if (item->length < 8) {
        strncpy(valstr, "INVALID", len);
        return valstr;
    }

    uplink = (uint32_t *)item->valptr;
    downlink = uplink + 1;

    snprintf(valstr, len, "Uplink=%u  Downlink=%u", ntohl(*uplink),
            ntohl(*downlink));
    return valstr;
}

static char *stringify_3gimei(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len) {

    uint8_t *ptr = (uint8_t *)item->valptr;
    char *nextwrite = valstr;
    int i;

    for (i = 0; i < item->length; i++) {
        uint8_t byteval;

        byteval = *ptr;

        if ((byteval & 0x0f) < 10) {
            *nextwrite = '0' + (byteval & 0x0f);
            nextwrite ++;
        }

        if (nextwrite - valstr >= len - 1) {
            break;
        }

        if (((byteval & 0xf0) >> 4) < 10) {
            *nextwrite = '0' + ((byteval & 0xf0) >> 4);
            nextwrite ++;
        }

        if (nextwrite - valstr >= len - 1) {
            valstr[len - 1] = '\0';
            return valstr;
        }

        ptr++;
    }

    if (nextwrite == valstr) {
        return NULL;
    }

    *nextwrite = '\0';

    return valstr;
}

static inline int stringify_mcc_mnc(uint8_t *todecode, int decodelen,
        char *valstr, int len) {

    char *nextwrite = valstr;
    uint8_t byteval;

    if (decodelen < 3) {
        return 0;
    }

    if (len < 9) {
        return 0;
    }

    /* MCC */
    byteval = *todecode;

    if ((byteval & 0x0f) < 10) {
        *nextwrite = '0' + (byteval & 0x0f);
        nextwrite ++;
    }

    if (((byteval & 0xf0) >> 4) < 10) {
        *nextwrite = '0' + ((byteval & 0xf0) >> 4);
        nextwrite ++;
    }

    todecode ++;
    byteval = *todecode;

    if ((byteval & 0x0f) < 10) {
        *nextwrite = '0' + (byteval & 0x0f);
        nextwrite ++;
    }

    *nextwrite = '-';
    nextwrite ++;

    /* MNC */
    if (((byteval & 0xf0) >> 4) < 10) {
        *nextwrite = '0' + ((byteval & 0xf0) >> 4);
        nextwrite ++;
    }

    todecode ++;
    byteval = *todecode;

    if ((byteval & 0x0f) < 10) {
        *nextwrite = '0' + (byteval & 0x0f);
        nextwrite ++;
    }

    if (((byteval & 0xf0) >> 4) < 10) {
        *nextwrite = '0' + ((byteval & 0xf0) >> 4);
        nextwrite ++;
    }

    *nextwrite = '-';
    nextwrite ++;
    return nextwrite - valstr;
}

static inline int decode_tai_to_string(uint8_t *taistart, int rem,
        char *writeptr, int writelen) {
    char *nextwrite;
    int used = 0;
    char tac[24];

    used = stringify_mcc_mnc(taistart, rem, writeptr, writelen);

    if (used == 0 || used >= writelen) {
        return 0;
    }

    nextwrite = writeptr + used;
    snprintf(tac, 24, "%04x", ntohs(*((uint16_t *)(taistart + 3))));

    if (strlen(tac) > writelen - used) {
        return 0;
    }

    memcpy(nextwrite, tac, strlen(tac));
    used += strlen(tac);
    return used;
}

static inline int decode_ecgi_to_string(uint8_t *ecgistart, int rem,
        char *writeptr, int writelen) {

    char *nextwrite;
    int used = 0;
    char eci[24];

    used = stringify_mcc_mnc(ecgistart, rem, writeptr, writelen);
    if (used == 0 || used >= writelen) {
        return 0;
    }

    nextwrite = writeptr + used;
    snprintf(eci, 24, "%07x", ntohl(*((uint32_t *)(ecgistart + 3))));

    if (strlen(eci) > writelen - used) {
        return 0;
    }
    memcpy(nextwrite, eci, strlen(eci));
    used += strlen(eci);

    return used;
}

static inline int decode_macro_enodeb_to_string(uint8_t *macrostart, int rem,
        char *writeptr, int writelen) {

    char *nextwrite;
    int used = 0;
    char enodeb[24];
    uint8_t id[4];
    uint32_t id_32;

    used = stringify_mcc_mnc(macrostart, rem, writeptr, writelen);

    if (used == 0 || used >= writelen) {
        return 0;
    }

    nextwrite = writeptr + used;

    id[0] = 0;
    memcpy(&(id[1]), macrostart + 3, 3);

    /* mask SMeNB bit in extended version */
    id[1] &= (0x1F);
    memcpy(&id_32, id, sizeof(uint32_t));

    snprintf(enodeb, 24, "%07x", ntohl(id_32));

    if (strlen(enodeb) > writelen - used) {
        return 0;
    }
    memcpy(nextwrite, enodeb, strlen(enodeb));
    used += strlen(enodeb);

    return used;
}

static inline int decode_lai_to_string(uint8_t *laistart, int rem,
        char *writeptr, int writelen) {

    char *nextwrite;
    int used = 0;
    char lac[24];

    used = stringify_mcc_mnc(laistart, rem, writeptr, writelen);

    if (used == 0 || used >= writelen) {
        return 0;
    }

    nextwrite = writeptr + used;
    snprintf(lac, 24, "%04x", ntohs(*((uint16_t *)(laistart + 3))));

    if (strlen(lac) > writelen - used) {
        return 0;
    }
    memcpy(nextwrite, lac, strlen(lac));
    used += strlen(lac);

    return used;
}

static inline int decode_cgi_to_string(uint8_t *cgistart, int rem,
        char *writeptr, int writelen) {

    char *nextwrite;
    int used = 0;
    char lac[24];
    char cellid[24];

    /* NOTE: SAI, RAI and CGI are basically the same format.
     * SAI has a SAC instead of a cell ID.
     * RAI has a RAC instead of a cell ID.
     * We can reuse this method to decode all of these location types.
     */

    used = stringify_mcc_mnc(cgistart, rem, writeptr, writelen);

    if (used == 0 || used >= writelen) {
        return 0;
    }

    nextwrite = writeptr + used;
    snprintf(lac, 24, "%04x", ntohs(*((uint16_t *)(cgistart + 3))));
    snprintf(cellid, 24, "%04x", ntohs(*((uint16_t *)(cgistart + 5))));

    if (strlen(lac) + strlen(cellid) + 1 > writelen - used) {
        return 0;
    }

    memcpy(nextwrite, lac, strlen(lac));
    nextwrite += strlen(lac);
    used += strlen(lac);

    *nextwrite = '-';
    nextwrite ++;

    memcpy(nextwrite, cellid, strlen(cellid));
    used += strlen(cellid) + 1;
    return used;

}

static char *stringify_tai(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len) {

    memset(valstr, 0, len);
    if (decode_tai_to_string(item->valptr, item->length, valstr, len) == 0) {
        return NULL;
    }
    return valstr;
}

static char *stringify_ecgi(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len) {

    memset(valstr, 0, len);
    if (decode_ecgi_to_string(item->valptr, item->length, valstr, len) == 0) {
        return NULL;
    }
    return valstr;
}

static char *stringify_sai(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len) {

    memset(valstr, 0, len);
    /* INTENTIONAL use of "cgi" here */
    if (decode_cgi_to_string(item->valptr, item->length, valstr, len) == 0) {
        return NULL;
    }
    return valstr;
}

static char *stringify_cgi(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len) {

    memset(valstr, 0, len);
    if (decode_cgi_to_string(item->valptr, item->length, valstr, len) == 0) {
        return NULL;
    }
    return valstr;
}

static char *stringify_sequenced_primitives(char *sequence_name,
        wandder_decoder_t *dec, char *space, int spacelen, int interpretas) {

    wandder_item_t *parent = dec->current;
    uint8_t *ptr = (uint8_t *)(parent->valptr);
    char *writer = space;
    int namelen = strlen(sequence_name);
    int first = 1, elipsis = 0;
    uint32_t outerseq_len = 0;
    int lenlen = 0;

    memset(space, 0, spacelen);

    assert(spacelen > namelen + 2);
    memcpy(writer, sequence_name, namelen);
    writer += namelen;

    *writer = ':';
    writer ++;
    *writer = ' ';
    writer ++;

    if (*ptr != 0x30) {
        return space;
    }
    ptr ++;
    outerseq_len = decode_length_field(ptr,
            parent->length - (ptr - parent->valptr), &lenlen);
    if (outerseq_len == 0) {
        return space;
    }
    ptr += lenlen;

    if (interpretas == WANDDER_TAG_INTEGER_SEQUENCE) {
        while (ptr - parent->valptr < parent->length) {
            char tmp[1024];
            int tmplen;
            int64_t nextint;
            uint32_t nextintlen;

            assert((*ptr) == WANDDER_TAG_INTEGER);
            ptr ++;
            /* integer len should always be a single byte (?) */
            nextintlen = (uint8_t)(*ptr);
            ptr ++;

            nextint = wandder_decode_integer_value(ptr, nextintlen);
            tmplen = snprintf(tmp, 1024, "%" PRId64, nextint);

            // +2 for the preceding ', ' and +5 to leave room for an elipsis
            // at the end if we run out of room
            if (tmplen > 0 && spacelen - (writer - space) > tmplen + 2 + 5) {
                if (!first) {
                    *writer = ',';
                    writer ++;
                    *writer = ' ';
                    writer ++;
                } else {
                    first = 0;
                }
                memcpy(writer, tmp, tmplen);
                writer += tmplen;
            } else if (tmplen > 0 && !elipsis && !first &&
                    spacelen - (writer - space) > 5) {
                memcpy(writer, ", ...", 5);
                writer += 5;
                elipsis = 1;
            }

            ptr += nextintlen;
        }
    } else if (interpretas == WANDDER_TAG_UTF8STR) {
        while (ptr - parent->valptr < parent->length) {
            int lenlen = 0;
            uint32_t strlength = 0;

            assert((*ptr) == WANDDER_TAG_UTF8STR);
            ptr ++;

            strlength = decode_length_field(ptr,
                    parent->length - (ptr - parent->valptr), &lenlen);

            if (strlength == 0) {
                break;
            } else if (strlength == 0xFFFFFFFF) {
                /* TODO handle indefinite length fields... */
                break;
            }
            ptr += lenlen;
            if (spacelen - (writer - space) > strlength + 2) {
                if (!first) {
                    *writer = ',';
                    writer ++;
                    *writer = ' ';
                    writer ++;
                } else {
                    first = 0;
                }
                memcpy(writer, ptr, strlength);
                writer += strlength;
            }
            ptr += strlength;
        }
    }

    /* TODO add code for other primitive types if they crop up */

    return space;

}

static char *stringify_eps_rat_type(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len) {

    uint8_t *ptr = item->valptr;

    if (len <= 0 || valstr == NULL) {
        return NULL;
    }
    memset(valstr, 0, len);

    if (item->length < 1) {
        return NULL;
    }

    switch(*ptr) {
        case 1:
            strncpy(valstr, "UTRAN", len);
            break;
        case 2:
            strncpy(valstr, "GERAN", len);
            break;
        case 3:
            strncpy(valstr, "WLAN", len);
            break;
        case 4:
            strncpy(valstr, "GAN", len);
            break;
        case 5:
            strncpy(valstr, "HSPA Evolution", len);
            break;
        case 6:
            strncpy(valstr, "EUTRAN", len);
            break;
        case 7:
            strncpy(valstr, "Virtual", len);
            break;
        case 8:
            strncpy(valstr, "EUTRAN-NB-IoT", len);
            break;
        case 9:
            strncpy(valstr, "LTE-M", len);
            break;
        case 10:
            strncpy(valstr, "NR", len);
            break;
        default:
            snprintf(valstr, len, "Unknown RAT Type: %u\n", *ptr);
            break;
    }

    return valstr;
}


static char *stringify_eps_attach_type(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len) {

    uint8_t *ptr = item->valptr;
    uint8_t epsval = (*ptr) & 0x07;

    if (len <= 0 || valstr == NULL) {
        return NULL;
    }
    memset(valstr, 0, len);

    if (item->length != 1) {
        return NULL;
    }
    switch(epsval) {
        case 1:
            strncpy(valstr, "EPS Attach", len);
            break;
        case 2:
            strncpy(valstr, "Combined EPS/IMSI Attach", len);
            break;
        case 3:
            strncpy(valstr, "EPS RLOS Attach", len);
            break;
        case 6:
            strncpy(valstr, "EPS Emergency Attach", len);
            break;
        case 7:
            strncpy(valstr, "(reserved)", len);
            break;
        default:
            strncpy(valstr, "EPS Attach (defaulted)", len);
    }

    return valstr;
}

static char *stringify_uli(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len) {

    uint8_t *ptr = item->valptr;
    uint8_t flags;
    uint8_t used = 0;
    uint16_t f = 0x01;
    char *write = valstr;
    int write_rem = len - 1;
    int res;

    if (len == 0 || valstr == NULL) {
        return NULL;
    }
    memset(valstr, 0, len);
    flags = item->valptr[0];

    ptr = ptr + 1;
    used = 1;

    while (f < 256) {
        res = -1;
        ptr = item->valptr + used;

        if (f == 0x01 && (f & flags)) {
            /* CGI */
            if (write_rem < 6) {
                return NULL;
            }
            memcpy(write, " CGI: ", 6);
            write += 6;
            write_rem -= 6;

            res = decode_cgi_to_string(ptr, item->length - used,
                    write, write_rem);
            used += 7;
        } else if (f == 0x02 && (f & flags)) {
            /* SAI */
            if (write_rem < 6) {
                return NULL;
            }
            memcpy(write, " SAI: ", 6);
            write += 6;
            write_rem -= 6;
            /* INTENTIONAL use of "cgi" here */
            res = decode_cgi_to_string(ptr, item->length - used,
                    write, write_rem);
            used += 7;
        } else if (f == 0x04 && (f & flags)) {
            /* RAI */
            if (write_rem < 6) {
                return NULL;
            }
            memcpy(write, " RAI: ", 6);
            write += 6;
            write_rem -= 6;
            /* INTENTIONAL use of "cgi" here */
            res = decode_cgi_to_string(ptr, item->length - used,
                    write, write_rem);
            used += 7;
        } else if (f == 0x08 && (f & flags)) {
            /* TAI */
            if (write_rem < 6) {
                return NULL;
            }
            memcpy(write, " TAI: ", 6);
            write += 6;
            write_rem -= 6;
            res = decode_tai_to_string(ptr, item->length - used,
                    write, write_rem);
            used += 5;
        } else if (f == 0x10 && (f & flags)) {
            /* ECGI */
            if (write_rem < 7) {
                return NULL;
            }
            memcpy(write, " ECGI: ", 7);
            write += 7;
            write_rem -= 7;
            res = decode_ecgi_to_string(ptr, item->length - used,
                    write, write_rem);
            used += 7;
        } else if (f == 0x20 && (f & flags)) {
            /* LAI */
            if (write_rem < 6) {
                return NULL;
            }
            memcpy(write, " LAI: ", 6);
            write += 6;
            write_rem -= 6;
            res = decode_lai_to_string(ptr, item->length - used,
                    write, write_rem);
            used += 5;
        } else if (f == 0x40 && (f & flags)) {
            /* Macro eNodeB ID */
            if (write_rem < 18) {
                return NULL;
            }
            memcpy(write, " Macro eNodeB ID: ", 18);
            write += 18;
            write_rem -= 18;
            res = decode_macro_enodeb_to_string(ptr, item->length - used,
                    write, write_rem);
            used += 6;
        } else if (f == 0x80 && (f & flags)) {
            /* Extended Macro eNodeB ID */
            if (write_rem < 22) {
                return NULL;
            }
            memcpy(write, " Ext Macro eNodeB ID: ", 22);
            write += 22;
            write_rem -= 22;
            /* same decoding method as macro_enodeb (intentional) */
            res = decode_macro_enodeb_to_string(ptr, item->length - used,
                    write, write_rem);
            used += 6;
        }

        if (res == -1) {
            f *= 2;
            continue;
        }

        if (res == 0) {
            return NULL;
        }
        assert(res <= write_rem);

        write += res;
        write_rem -= res;
        f *= 2;
    }
    return valstr;
}

static char *stringify_bytes_as_hex(wandder_etsispec_t *etsidec,
        wandder_item_t *item, char *valstr, int len) {

    int i;
    char *nextwrite;

    if (len <= 4) {
        return NULL;
    }

    memset(valstr, 0, len);
    memcpy(valstr, "0x", 2);

    nextwrite = valstr + 2;

    for (i = 0; i < item->length; i++) {
        char staged[3];

        snprintf(staged, 3, "%02x", (unsigned int) *(((uint8_t *)(item->valptr)) + i));
        memcpy(nextwrite, staged, 2);
        nextwrite += 2;
        if (nextwrite - valstr >= len - 2) {
            break;
        }
    }

    return valstr;

}

static int decrypt_encryption_container(wandder_etsispec_t *etsidec,
        wandder_item_t *item) {

    wandder_decoder_t *dec = NULL;
    int thisret = 0, ret;
    uint32_t ident;
    char valstr[16384];

    dec = init_wandder_decoder(dec, item->valptr, item->length, 0);

    /* get the encryption type */
    QUICK_DECODE(thisret);
    if (ident != 0) {
        return 0;
    }

    etsidec->encrypt_method = wandder_get_integer_value(dec->current, NULL);

    /* decrypt the encrypted payload */
    QUICK_DECODE(thisret);
    if (ident != 1) {
        return 0;
    }

    if (decrypt_encrypted_payload_item(etsidec, dec->current, valstr,
            16384) == NULL) {
        thisret = 1;
    }
    free_wandder_decoder(dec);
    return thisret;
}

#define DECRYPT_INIT \
    decrypted = calloc(1, item->length * 2); \
    decrypt_size = item->length * 2; \
    ciphertext = calloc(1, item->length + 1); \
    memcpy(ciphertext, (uint8_t *)(item->valptr), item->length); \
    seqdec = init_wandder_decoder(seqdec, etsidec->dec->source, \
            etsidec->dec->sourcelen, 0); \
    seqno = decode_sequence_number(seqdec); \
    seq32 = (int32_t)(seqno & 0xFFFFFFFF); \
    free_wandder_decoder(seqdec); \

static char *decrypt_encrypted_payload_item(wandder_etsispec_t *etsidec,
        wandder_item_t *item, char *valstr, int len) {

    uint8_t *ciphertext = NULL;
    wandder_decoder_t *seqdec = NULL;
    int64_t seqno;
    int32_t seq32;
    char *keyenv;
    uint8_t *decrypted = NULL;
    int decrypt_size;
    int dlen = 0;

    keyenv = getenv("LIBWANDDER_ETSILI_DECRYPTION_KEY");
    if (etsidec->encrypt_method == WANDDER_ENCRYPTION_TYPE_NONE) {
        etsidec->decrypted = calloc(1, item->length);
        memcpy(etsidec->decrypted, item->valptr, item->length);
        etsidec->decrypt_size = item->length;
        goto decryptsuccess;
    } else if (etsidec->encrypt_method == WANDDER_ENCRYPTION_TYPE_AES_192_CBC) {
        DECRYPT_INIT
    } else if (etsidec->encrypt_method == WANDDER_ENCRYPTION_TYPE_NOT_STATED) {
        goto decryptfail;
    } else {
        fprintf(stderr, "Unsupported encryption method: %d\n",
                etsidec->encrypt_method);
        goto decryptfail;
    }

    if (etsidec->encrypt_method == WANDDER_ENCRYPTION_TYPE_AES_192_CBC) {
        char *dkey = NULL;
        if (etsidec->decryption_key) {
            dkey = etsidec->decryption_key;
        } else {
            dkey = keyenv;
        }

        if ((dlen = decrypt_payload_content_aes_192_cbc(ciphertext,
                item->length,
                dkey, seq32, (unsigned char *)decrypted, decrypt_size)) < 0) {
            goto decryptfail;
        }
    }

    /* Do some sanity checks on the decrypted content, just in case we
     * were given the wrong key...
     */

    if (decrypted[0] != 0x30) {
        fprintf(stderr, "Decrypted payload does not begin with expected 0x30 byte -- provided key is probably incorrect?\n");
        goto decryptfail;
    }

    if (decrypt_length_sanity_check(decrypted, (uint64_t)dlen) == 0) {
        fprintf(stderr, "Decrypted payload does not appear to have a valid length field -- provided key is probably incorrect?\n");
        goto decryptfail;
    }

    free(ciphertext);
    etsidec->decrypted = decrypted;
    etsidec->decrypt_size = decrypt_size;

decryptsuccess:
    etsidec->decrypt_dec = init_wandder_decoder(etsidec->decrypt_dec,
            etsidec->decrypted, etsidec->decrypt_size, 0);

    return NULL;

decryptfail:
    if (ciphertext) {
        free(ciphertext);
    }
    if (decrypted) {
        free(decrypted);
    }
    /* unable to decrypt, fall back to hex decoding */
    return stringify_bytes_as_hex(etsidec, item, valstr, len);

}

static char *stringify_domain_name(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len) {

    int eos, indx;
    memset(valstr, 0, len);

    /* TODO handle compressed name segments */

    /* length - 1 because we're skipping the first byte
     * len - 1 because we need to save room for a null byte
     */
    if (item->length - 1 > len - 1) {
        memcpy(valstr, item->valptr + 1, len - 1);
        eos = len - 1;
    } else {
        memcpy(valstr, item->valptr + 1, item->length - 1);
        eos = item->length - 1;
    }

    indx = (*((uint8_t *)item->valptr));

    while (indx < eos) {
        uint8_t next = (uint8_t)(valstr[indx]);

        valstr[indx] = '.';
        indx += (1 + next);
    }

    return valstr;

}

static const char *stringify_ipaddress(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len) {

    int family;
    void *addr;
    struct in_addr in;
    struct in6_addr in6;

    if (item->length == 4) {
        memcpy(&(in.s_addr), item->valptr, item->length);
        family = AF_INET;
        addr = &in;

    } else if (item->length == 16) {
        memcpy(&(in6.s6_addr), item->valptr, item->length);
        family = AF_INET6;
        addr = &in6;
    } else {
        fprintf(stderr, "Unexpected IP address length: %lu\n", (long) item->length);
        return NULL;
    }

    return inet_ntop(family, addr, valstr, len);

}

/* These functions are hideous, but act as a C-compatible version of the
 * ASN.1 specification of the ETSI LI standard.
 *
 * Try not to look too closely at this stuff unless you really need to.
 */


static char *interpret_enum(wandder_etsispec_t *etsidec, wandder_item_t *item,
        wandder_dumper_t *curr, char *valstr, int len) {

    uint32_t intlen = 0;
    int64_t enumval = 0;
    char *name = NULL;

    /* First, decode the valptr as though it were an integer */
    enumval = wandder_get_integer_value(item, &intlen);

    if (intlen == 0) {
        fprintf(stderr, "Failed to interpret enum value as an integer.\n");
        return NULL;
    }

    if (item->identifier == 1 && curr == &(etsidec->ipaddress)) {
        /* iP-type */
        switch(enumval) {
            case 0:
                name = "IPv4";
                break;
            case 1:
                name = "IPv6";
                break;
        }
    }

    else if (item->identifier == 3 && curr == &(etsidec->ipaddress)) {
        /* iP-assignment */
        switch(enumval) {
            case 1:
                name = "Static";
                break;
            case 2:
                name = "Dynamic";
                break;
            case 3:
                name = "Not Known";
                break;
        }
    }

    else if (item->identifier == 0 && curr == &(etsidec->ccpayload)) {
        /* payloadDirection */
        switch(enumval) {
            case 0:
                name = "fromTarget";
                break;
            case 1:
                name = "toTarget";
                break;
            case 2:
                name = "indeterminate";
                break;
            case 3:
                name = "combined";
                break;
            case 4:
                name = "notApplicable";
                break;
        }
    }

    else if (item->identifier == 1 && curr == &(etsidec->integritycheck)) {
        /* checkType */
        switch (enumval) {
            case 1:
                name = "Hash";
                break;
            case 2:
                name = "DSS/DSA signature";
                break;
        }
    }

    else if (item->identifier == 2 && curr == &(etsidec->integritycheck)) {
        /* dataType */
        switch (enumval) {
            case 1:
                name = "IRI";
                break;
            case 2:
                name = "CC";
                break;
            case 3:
                name = "ILHI";
                break;
        }
    }
    else if (item->identifier == 4 && curr == &(etsidec->integritycheck)) {
        /* dataType */
        switch (enumval) {
            case 1:
                name = "SHA-1";
                break;
            case 2:
                name = "SHA-256";
                break;
            case 3:
                name = "SHA-384";
                break;
            case 4:
                name = "SHA-512";
                break;
        }
    }

    else if ((item->identifier == 4 && curr == &(etsidec->ccpayload)) ||
            (item->identifier == 4 && curr == &(etsidec->iripayload)) ||
            (item->identifier == 8 && curr == &(etsidec->psheader))) {
        /* timeStampQualifier */
        switch(enumval) {
            case 0:
                name = "unknown";
                break;
            case 1:
                name = "timeOfInterception";
                break;
            case 2:
                name = "timeOfMediation";
                break;
            case 3:
                name = "timeOfAggregation";
                break;
        }
    }

    else if (item->identifier == 0 && curr == &(etsidec->ipiricontents)) {
        /* accessEventType */
        switch(enumval) {
            case 0:
                name = "accessAttempt";
                break;
            case 1:
                name = "accessAccept";
                break;
            case 2:
                name = "accessReject";
                break;
            case 3:
                name = "accessFailed";
                break;
            case 4:
                name = "sessionStart";
                break;
            case 5:
                name = "sessionEnd";
                break;
            case 6:
                name = "interimUpdate";
                break;
            case 7:
                name = "startOfInterceptionWithSessionActive";
                break;
            case 8:
                name = "accessEnd";
                break;
            case 9:
                name = "endOfInterceptionWithSessionActive";
                break;
            case 10:
                name = "unknown";
                break;
        }
    }

    else if (item->identifier == 2 && curr == &(etsidec->ipiricontents)) {
        /* internetAccessType */
        switch(enumval) {
            case 0:
                name = "undefined";
                break;
            case 1:
                name = "dialUp";
                break;
            case 2:
                name = "xDSL";
                break;
            case 3:
                name = "cableModem";
                break;
            case 4:
                name = "LAN";
                break;
            case 5:
                name = "wirelessLAN";
                break;
            case 6:
                name = "Fiber";
                break;
            case 7:
                name = "WIMAX/HIPERMAN";
                break;
            case 8:
                name = "Satellite";
                break;
            case 9:
                name = "Wireless-Other";
                break;
        }
    }

    else if (item->identifier == 3 && curr == &(etsidec->ipiricontents)) {
        /* iPVersion */
        switch(enumval) {
            case 1:
                name = "IPv4";
                break;
            case 2:
                name = "IPv6";
                break;
            case 3:
                name = "IPv4-IPv6";
                break;
        }
    }

    else if (item->identifier == 12 && curr == &(etsidec->ipiricontents)) {
        /* endReason */
        switch(enumval) {
            case 0:
                name = "undefined";
                break;
            case 1:
                name = "regularLogOff";
                break;
            case 2:
                name = "connectionLoss";
                break;
            case 3:
                name = "connectionTimeout";
                break;
            case 4:
                name = "leaseExpired";
                break;
        }
    }

    else if (item->identifier == 22 && curr == &(etsidec->ipiricontents)) {
        /* authenticationType */
        switch(enumval) {
            case 0:
                name = "unknown";
                break;
            case 1:
                name = "static";
                break;
            case 2:
                name = "Radius-AAA";
                break;
            case 3:
                name = "DHCP-AAA";
                break;
            case 4:
                name = "Diameter-AAA";
                break;
        }
    }

    else if (item->identifier == 0 && curr == &(etsidec->iripayload)) {
        /* iRIType */
        switch(enumval) {
            case 1:
                name = "IRI-Begin";
                break;
            case 2:
                name = "IRI-End";
                break;
            case 3:
                name = "IRI-Continue";
                break;
            case 4:
                name = "IRI-Report";
                break;

        }
    }

    else if (item->identifier == 0 && curr == &(etsidec->operatorleamessage)) {
        /* messagePriority for operatorLeaMessage */
        switch(enumval) {
            case 1:
                name = "Error";
                break;
            case 2:
                name = "Informational";
                break;
        }
    }

    else if (item->identifier == 2 && curr == &(etsidec->ipmmcc)) {
        /* frameType for iPMMCC */
        switch(enumval) {
            case 0:
                name = "ipFrame";
                break;
            case 1:
                name = "udpFrame";
                break;
            case 2:
                name = "rtpFrame";
                break;
            case 3:
                name = "audioFrame";
                break;
            case 4:
                name = "tcpFrame";
                break;
            case 5:
                name = "artificialRtpFrame";
                break;
            case 6:
                name = "udptlFrame";
                break;
        }
    }

    else if (item->identifier == 4 && curr == &(etsidec->ipmmcc)) {
        /* mMCCprotocol for iPMMCC */
        switch(enumval) {
            case 0:
                name = "rTP";
                break;
            case 1:
                name = "mSRP";
                break;
            case 2:
                name = "uDPTL";
                break;
        }
    }

    else if (item->identifier == 4 && (curr == &(etsidec->umtsiri_params) ||
                curr == &(etsidec->epsiri_params))) {
        /* initiator for uMTSIRI */
        switch(enumval) {
            case 0:
                name = "not-Available";
                break;
            case 1:
                name = "originating-Target";
                break;
            case 2:
                name = "terminating-Target";
                break;
        }
    }
    else if (item->identifier == 23 && curr == &(etsidec->umtsiri_params)) {
        /* iRIversion for uMTSIRI */
        switch(enumval) {
            case 2:
                name = "version2";
                break;
            case 3:
                name = "version3";
                break;
            case 4:
                name = "version4";
                break;
            case 6:
                name = "version6";
                break;
            case 8:
                name = "lastVersion";
                break;
        }
    }
    else if (item->identifier == 20 && curr == &(etsidec->umtsiri_params)) {
        /* gPRSevent for uMTSIRI */
        switch (enumval) {
            case 1:
                name = "pDPContextActivation";
                break;
            case 2:
                name = "startOfInterceptionWithPDPContextActive";
                break;
            case 4:
                name = "pDPContextDeactivation";
                break;
            case 5:
                name = "gPRSAttach";
                break;
            case 6:
                name = "gPRSDetach";
                break;
            case 10:
                name = "locationInfoUpdate";
                break;
            case 11:
                name = "sMS";
                break;
            case 13:
                name = "pDPContextModification";
                break;
            case 14:
                name = "servingSystem";
                break;
            case 15:
                name = "startOfInterceptionWithMSAttached";
                break;
            case 16:
                name = "packetDataHeaderInformation";
                break;
            case 17:
                name = "hSS-Subscriber-Record-Change";
                break;
            case 18:
                name = "registration-Termination";
                break;
            case 19:
                name = "location-Up-Date";
                break;
            case 20:
                name = "cancel-Location";
                break;
            case 21:
                name = "register-Location";
                break;
            case 22:
                name = "location-Information-Request";
                break;
        }
    }
    else if (item->identifier == 1 && curr == &(etsidec->localtimestamp)) {
        /* winterSummerIndication from localTimestamp */
        switch(enumval) {
            case 0:
                name = "notProvided";
                break;
            case 1:
                name = "winterTime";
                break;
            case 2:
                name = "summerTime";
                break;
        }
    }
    else if (item->identifier == 0 && curr == &(etsidec->partyinfo)) {
        /* party-Qualifier for partyInformation */
        /* strangely, there's only one valid value for this enum */
        switch(enumval) {
            case 3:
                name = "gPRS-Target";
                break;
        }
    }
    else if (item->identifier == 1 && curr == &(etsidec->emailiri)) {
        /* email eventType */
        switch(enumval) {
            case 1:
                name = "e-mail-send";
                break;
            case 2:
                name = "e-mail-receive";
                break;
            case 3:
                name = "e-mail-download";
                break;
            case 4:
                name = "e-mail-logon-attempt";
                break;
            case 5:
                name = "e-mail-logon";
                break;
            case 6:
                name = "e-mail-logon-failure";
                break;
            case 7:
                name = "e-mail-logoff";
                break;
            case 8:
                name = "e-mail-partial-download";
                break;
            case 9:
                name = "e-mail-upload";
                break;
        }
    }
    else if (item->identifier == 8 && curr == &(etsidec->emailiri)) {
        /* E-mail-Protocol */
        switch(enumval) {
            case 1:
                name = "smtp";
                break;
            case 2:
                name = "pop3";
                break;
            case 3:
                name = "imap4";
                break;
            case 4:
                name = "webmail";
                break;
            case 255:
                name = "undefined";
                break;
        }
    }
    else if (item->identifier == 11 && curr == &(etsidec->emailiri)) {
        /* E-mail-Status */
        switch(enumval) {
            case 1:
                name = "status-unknown";
                break;
            case 2:
                name = "operation-failed";
                break;
            case 3:
                name = "operation-succeeded";
                break;
        }
    }
    else if (item->identifier == 17 && curr == &(etsidec->emailiri)) {
        /* e-mail-Sender-Validity */
        switch(enumval) {
            case 0:
                name = "validated";
                break;
            case 1:
                name = "nonvalidated";
                break;
        }
    }
    else if (item->identifier == 1 && curr == &(etsidec->emailcc)) {
        /* e-mail-Sender-Validity */
        switch(enumval) {
            case 1:
                name = "ip-packet";
                break;
            case 2:
                name = "application";
                break;
        }
    } else if (
            (item->identifier == 2 && curr == &(etsidec->pop3aaainformation)) ||
            (item->identifier == 4 && curr == &(etsidec->asmtpaaainformation)))
    {
        /* aAAResult */
        switch(enumval) {
            case 1:
                name = "resultUnknown";
                break;
            case 2:
                name = "aAAFailed";
                break;
            case 3:
                name = "aAASucceeded";
                break;
        }
    } else if (item->identifier == 1 &&
            curr == &(etsidec->asmtpaaainformation)) {
        /* AAAauthMethod */
        switch(enumval) {
            case 1:
                name = "undefinedAuthMethod";
                break;
            case 2:
                name = "cramMD5";
                break;
            case 3:
                name = "digestMD5";
                break;
        }
    }

	/*
	 * Adding encryptionType and encryptedPayloadType, WPvS
	 *
	 */
    else if (item->identifier == 0 && curr == &(etsidec->encryptioncontainer)) {
        /* EncryptionType */
        switch(enumval) {
            case 1:
                name = "None";
                break;
            case 2:
                name = "national-option";
                break;
            case 3:
                name = "AES-192-CBC";
                break;
            case 4:
                name = "AES-256-CBC";
                break;
            case 5:
                name = "blowfish-192-CBC";
                break;
            case 6:
                name = "blowfish-256-CBC";
                break;
            case 7:
                name = "threedes-cbc";
                break;
        }

        /* Save the encryption type so we can decrypt the upcoming payload. */
        etsidec->encrypt_method = enumval;
    }

    else if (item->identifier == 2 && curr == &(etsidec->encryptioncontainer)) {
        /* EncryptionPayloadType */
        switch(enumval) {
            case 1:
                name = "Unknown";	
                break;
            case 2:
                name = "part2";
                break;
            case 3:
                name = "part3";
                break;
            case 4:
                name = "part4";
                break;
            case 5:
                name = "part5";
                break;
            case 6:
                name = "part6";
                break;
            case 7:
                name = "part7";
                break;
            case 8:
                name = "part1";
                break;
        }
    } else if (item->identifier == 20 && curr == &(etsidec->epsiri_params)) {
        /* ePSEvent */
        switch(enumval) {
            case 1:
                name = "pDPContextActivation";
                break;
            case 2:
                name = "startOfInterceptionWithPDPContextActive";
                break;
            case 4:
                name = "pDPContextDeactivation";
                break;
            case 5:
                name = "gPRSAttach";
                break;
            case 6:
                name = "gPRSDetach";
                break;
            case 10:
                name = "locationInfoUpdate";
                break;
            case 11:
                name = "sMS";
                break;
            case 13:
                name = "pDPContextModification";
                break;
            case 14:
                name = "servingSystem";
                break;
            case 15:
                name = "startofInterceptionWithMSAttached";
                break;
            case 16:
                name = "e-UTRANAttach";
                break;
            case 17:
                name = "e-UTRANDetach";
                break;
            case 18:
                name = "bearerActivation";
                break;
            case 19:
                name = "startOfInterceptionWithActiveBearer";
                break;
            case 20:
                name = "bearerModification";
                break;
            case 21:
                name = "bearerDeactivation";
                break;
            case 22:
                name = "uERequestedBearerResourceModification";
                break;
            case 23:
                name = "uERequestedPDNConnectivity";
                break;
            case 24:
                name = "uERequestedPDNDisconnection";
                break;
            case 25:
                name = "trackingAreaEpsLocationUpdate";
                break;
            case 26:
                name = "servingEvolvedPacketSystem";
                break;
            case 27:
                name = "pMIPAttachTunnelActivation";
                break;
            case 28:
                name = "pMIPDetachTunnelDeactivation";
                break;
            case 29:
                name = "startOfInterceptionWithActivePMIPTunnel";
                break;
            case 30:
                name = "pMIPPdnGwInitiatedPdnDisconnection";
                break;
            case 31:
                name = "mIPRegistrationTunnelActivation";
                break;
            case 32:
                name = "mIPDeregistrationTunnelDeactivation";
                break;
            case 33:
                name = "startOfInterceptionWithActiveMIPTunnel";
                break;
            case 34:
                name = "dSMIPRegistrationTunnelActivation";
                break;
            case 35:
                name = "dSMIPDeregistrationTunnelDeactivation";
                break;
            case 36:
                name = "startOfInterceptionWithActiveDsmipTunnel";
                break;
            case 37:
                name = "dSMipHaSwitch";
                break;
            case 38:
                name = "pMIPResourceAllocationDeactivation";
                break;
            case 39:
                name = "mIPResourceAllocationDeactivation";
                break;
            case 40:
                name = "pMIPsessionModification";
                break;
            case 41:
                name = "startOfInterceptionWithEUTRANAttachedUE";
                break;
            case 42:
                name = "dSMIPSessionModification";
                break;
            case 43:
                name = "packetDataHeaderInformation";
                break;
            case 44:
                name = "hSS-Subscriber-Record-Change";
                break;
            case 45:
                name = "registration-Termination";
                break;
            case 46:
                name = "location-Up-Date";
                break;
            case 47:
                name = "cancel-Location";
                break;
            case 48:
                name = "register-Location";
                break;
            case 49:
                name = "location-Information-Request";
                break;
            case 50:
                name = "proSeRemoteUEReport";
                break;
            case 51:
                name = "proSeRemoteUEStartOfCommunication";
                break;
            case 52:
                name = "proSeRemoteUEEndOfCommunication";
                break;
            case 53:
                name = "startOfLIwithProSeRemoteUEOngoingComm";
                break;
            case 54:
                name = "startOfLIforProSeUEtoNWRelay";
                break;
            case 55:
                name = "scefRequestednonIPPDNDisconnection";
                break;

        }
    } else if (item->identifier == 29 && curr == &(etsidec->epsiri_params)) {
        /* iMSEvent */
        switch(enumval) {
            case 1:
                name = "unfilteredSIPmessage";
                break;
            case 2:
                name = "sIPheaderOnly";
                break;
            case 3:
                name = "decryptionKeysAvailable";
                break;
            case 4:
                name = "startOfInterceptionForIMSEstablishedSession";
                break;
            case 5:
                name = "xCAPRequest";
                break;
            case 6:
                name = "xCAPResponse";
                break;
            case 7:
                name = "ccUnavailable";
                break;
            case 8:
                name = "sMSOverIMS";
                break;
            case 9:
                name = "servingSystem";
                break;
            case 10:
                name = "subscriberRecordChange";
                break;
            case 11:
                name = "registrationTermination";
                break;
            case 12:
                name = "locationInformationRequest";
                break;
        }
    } else if (item->identifier == 34 && curr == &(etsidec->epsiri_params)) {
        /* ldiEvent */
        switch(enumval) {
            case 1:
                name = "targetEntersIA";
                break;
            case 2:
                name = "targetLeavesIA";
                break;
        }
    } else if ((item->identifier == 10 || item->identifier == 21)
            && curr == &(etsidec->eps_gtpv2_params)) {
        /* typeOfBearer */
        switch(enumval) {
            case 1:
                name = "defaultBearer";
                break;
            case 2:
                name = "dedicatedBearer";
                break;
        }
    } else if (item->identifier == 6 && curr == &(etsidec->ulic_header)) {
        /* TPDU-direction */
        switch(enumval) {
            case 1:
                name = "from-target";
                break;
            case 2:
                name = "to-target";
                break;
            case 3:
                name = "unknown";
                break;
        }
    } else if (item->identifier == 8 && curr == &(etsidec->ulic_header)) {
        /* ICE-type */
        switch(enumval) {
            case 1:
                name = "sgsn";
                break;
            case 2:
                name = "ggsn";
                break;
            case 3:
                name = "s-GW";
                break;
            case 4:
                name = "pDN-GW";
                break;
            case 5:
                name = "colocated-SAE-GWs";
                break;
            case 6:
                name = "ePDG";
                break;
        }
    }

    if (name != NULL) {
        snprintf(valstr, len, "%s", name);
        return name;
    }

    return NULL;
}

static void free_dumpers(wandder_etsispec_t *dec) {
    free(dec->ipvalue.members);
    free(dec->timestamp.members);
    free(dec->localtimestamp.members);
    free(dec->h323content.members);
    free(dec->h323message.members);
    free(dec->nationalipmmiri.members);
    free(dec->sipmessage.members);
    free(dec->ipmmiricontents.members);
    free(dec->ipmmiri.members);
    free(dec->additionalsignalling.members);
    free(dec->lipspdulocation.members);
    free(dec->epslocation.members);
    free(dec->datanodeaddress.members);
    free(dec->ipaddress.members);
    free(dec->ipcccontents.members);
    free(dec->ipmmcc.members);
    free(dec->ipcc.members);
    free(dec->epscc.members);
    free(dec->ulic_header.members);
    free(dec->netelid.members);
    free(dec->linetid.members);
    free(dec->networkidentifier.members);
    free(dec->location.members);
    free(dec->partyinfo.members);
    free(dec->partyidentity.members);
    free(dec->servicesdatainfo.members);
    free(dec->gprsparams.members);
    free(dec->hi2op_cid.members);
    free(dec->hi2op_netid.members);
    free(dec->cid.members);
    free(dec->msts.members);
    free(dec->cccontents.members);
    free(dec->ccpayload.members);
    free(dec->operatorleamessage.members);
    free(dec->option.members);
    free(dec->optionreq.members);
    free(dec->optionresp.members);
    free(dec->hi1notification.members);
    free(dec->hi1operation.members);
    free(dec->integritycheck.members);
    free(dec->tripayload.members);
    free(dec->ipiriid.members);
    free(dec->ipiricontents.members);
    free(dec->ipiri.members);
    free(dec->emailiri.members);
    free(dec->emailcc.members);
    free(dec->aaainformation.members);
    free(dec->pop3aaainformation.members);
    free(dec->asmtpaaainformation.members);
    free(dec->epsiri.members);
    free(dec->epsiri_params.members);
    free(dec->umtsqos.members);
    free(dec->eps_protconfigoptions.members);
    free(dec->eps_gtpv2_params.members);
    free(dec->umtsiri.members);
    free(dec->umtsiri_params.members);
    free(dec->iricontents.members);
    free(dec->iripayload.members);
    free(dec->payload.members);
    free(dec->psheader.members);
    free(dec->pspdu.members);
    free(dec->encryptioncontainer.members);
    free(dec->encryptedpayload.members);

}

static void init_dumpers(wandder_etsispec_t *dec) {

    size_t i;

    dec->ipvalue.membercount = 3;
    ALLOC_MEMBERS(dec->ipvalue);
    dec->ipvalue.members[0] = WANDDER_NOACTION;
    dec->ipvalue.members[1] =
        (struct wandder_dump_action) {
                .name = "iPBinaryAddress",
                .descend = NULL,
                .interpretas = WANDDER_TAG_BINARY_IP
        };
    dec->ipvalue.members[2] =
        (struct wandder_dump_action) {
                .name = "iPTextAddress",
                .descend = NULL,
                .interpretas = WANDDER_TAG_IA5
        };
    dec->ipvalue.sequence = WANDDER_NOACTION;

    dec->ipaddress.membercount = 6;
    ALLOC_MEMBERS(dec->ipaddress);
    dec->ipaddress.members[0] = WANDDER_NOACTION;
    dec->ipaddress.members[1] =
        (struct wandder_dump_action) {
                .name = "iP-type",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->ipaddress.members[2] =
        (struct wandder_dump_action) {
                .name = "iP-value",
                .descend = &dec->ipvalue,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->ipaddress.members[3] =
        (struct wandder_dump_action) {
                .name = "iP-assignment",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->ipaddress.members[4] =
        (struct wandder_dump_action) {
                .name = "iPv6PrefixLength",
                .descend = NULL,
                .interpretas = WANDDER_TAG_INTEGER
        };
    dec->ipaddress.members[5] =
        (struct wandder_dump_action) {
                .name = "iPv4SubnetMask",
                .descend = NULL,
                .interpretas = WANDDER_TAG_BINARY_IP
        };
    dec->ipaddress.sequence = WANDDER_NOACTION;

    dec->datanodeaddress.membercount = 3;
    ALLOC_MEMBERS(dec->datanodeaddress);
    dec->datanodeaddress.members[0] = WANDDER_NOACTION;
    dec->datanodeaddress.members[1] =
        (struct wandder_dump_action) {
                .name = "ipAddress",
                .descend = &(dec->ipaddress),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->datanodeaddress.members[2] = WANDDER_NOACTION;
    dec->datanodeaddress.sequence = WANDDER_NOACTION;

    dec->nationalipmmiri.membercount = 1;
    ALLOC_MEMBERS(dec->nationalipmmiri);
    dec->nationalipmmiri.members[0] =
        (struct wandder_dump_action) {
                .name = "countryCode",
                .descend = NULL,
                .interpretas = WANDDER_TAG_PRINTABLE
        };
    dec->nationalipmmiri.sequence = WANDDER_NOACTION;

    dec->localtimestamp.membercount = 2;
    ALLOC_MEMBERS(dec->localtimestamp);
    dec->localtimestamp.members[0] =
        (struct wandder_dump_action) {
                .name = "generalizedTime",
                .descend = NULL,
                .interpretas = WANDDER_TAG_GENERALTIME
        };
    dec->localtimestamp.members[1] =
        (struct wandder_dump_action) {
                .name = "winterSummerIndication",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->localtimestamp.sequence = WANDDER_NOACTION;

    dec->timestamp.membercount = 2;
    ALLOC_MEMBERS(dec->timestamp);
    dec->timestamp.members[0] =
        (struct wandder_dump_action) {
                .name = "localTime",
                .descend = &(dec->localtimestamp),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->timestamp.members[1] =
        (struct wandder_dump_action) {
                .name = "utcTime",
                .descend = NULL,
                .interpretas = WANDDER_TAG_UTCTIME
        };
    dec->timestamp.sequence = WANDDER_NOACTION;

    dec->h323content.membercount = 4;
    ALLOC_MEMBERS(dec->h323content);
    dec->h323content.members[0] =
        (struct wandder_dump_action) {
                .name = "h225CSMessageContent",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->h323content.members[1] =
        (struct wandder_dump_action) {
                .name = "h225RASMessageContent",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->h323content.members[2] =
        (struct wandder_dump_action) {
                .name = "h245MessageContent",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->h323content.members[3] =
        (struct wandder_dump_action) {
                .name = "genericMessageContent",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->h323content.sequence = WANDDER_NOACTION;

    dec->h323message.membercount = 3;
    ALLOC_MEMBERS(dec->h323message);
    dec->h323message.members[0] =
        (struct wandder_dump_action) {
                .name = "ipSourceAddress",
                .descend = &dec->ipaddress,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->h323message.members[1] =
        (struct wandder_dump_action) {
                .name = "ipDestinationAddress",
                .descend = &dec->ipaddress,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->h323message.members[2] =
        (struct wandder_dump_action) {
                .name = "h323Content",
                .descend = &dec->h323content,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->h323message.sequence = WANDDER_NOACTION;

    dec->sipmessage.membercount = 3;
    ALLOC_MEMBERS(dec->sipmessage);
    dec->sipmessage.members[0] =
        (struct wandder_dump_action) {
                .name = "ipSourceAddress",
                .descend = &dec->ipaddress,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->sipmessage.members[1] =
        (struct wandder_dump_action) {
                .name = "ipDestinationAddress",
                .descend = &dec->ipaddress,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->sipmessage.members[2] =
        (struct wandder_dump_action) {
                .name = "sIPContent",
                .descend = NULL,
                .interpretas = WANDDER_TAG_IPPACKET
        };
    dec->sipmessage.sequence = WANDDER_NOACTION;

    dec->ipmmiricontents.membercount = 4;
    ALLOC_MEMBERS(dec->ipmmiricontents);
    dec->ipmmiricontents.members[0] =
        (struct wandder_dump_action) {
                .name = "originalIPMMMessage",
                .descend = NULL,
                .interpretas = WANDDER_TAG_IPPACKET
        };
    dec->ipmmiricontents.members[1] =
        (struct wandder_dump_action) {
                .name = "sIPMessage",
                .descend = &dec->sipmessage,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->ipmmiricontents.members[2] =
        (struct wandder_dump_action) {
                .name = "h323Message",
                .descend = &dec->h323message,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->ipmmiricontents.members[3] =
        (struct wandder_dump_action) {
                .name = "nationalIPMMIRIParameters",
                .descend = &dec->nationalipmmiri,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->ipmmiricontents.sequence = WANDDER_NOACTION;

    dec->ipmmiri.membercount = 4;
    ALLOC_MEMBERS(dec->ipmmiri);
    dec->ipmmiri.members[0] =
        (struct wandder_dump_action) {
                .name = "iPMMIRIObjId",
                .descend = NULL,
                .interpretas = WANDDER_TAG_RELATIVEOID
        };
    dec->ipmmiri.members[1] =
        (struct wandder_dump_action) {
                .name = "iPMMIRIContents",
                .descend = &dec->ipmmiricontents,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->ipmmiri.members[2] =
        (struct wandder_dump_action) {
                .name = "targetLocation",
                .descend = &dec->lipspdulocation,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->ipmmiri.members[3] =
        (struct wandder_dump_action) {
                .name = "additionalSignalingSeq",
                .descend = &dec->additionalsignallingseq,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->ipmmiri.sequence = WANDDER_NOACTION;

    dec->lipspdulocation.membercount=5;
    ALLOC_MEMBERS(dec->lipspdulocation);
    dec->lipspdulocation.members[0] =
        (struct wandder_dump_action) {
                .name = "umtsHI2Location",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->lipspdulocation.members[1] =
        (struct wandder_dump_action) {
                .name = "epsLocation",
                .descend = &dec->epslocation,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->lipspdulocation.members[2] =
        (struct wandder_dump_action) {
                .name = "wlanLocationAttributes",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->lipspdulocation.members[3] =
        (struct wandder_dump_action) {
                .name = "eTSI671HI2Location",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->lipspdulocation.members[4] =
        (struct wandder_dump_action) {
                .name = "threeGPP33128UserLocation",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->lipspdulocation.sequence = WANDDER_NOACTION;

    dec->epslocation.membercount = 11;
    ALLOC_MEMBERS(dec->epslocation);
    dec->epslocation.members[0] = WANDDER_NOACTION;
    dec->epslocation.members[1] =
        (struct wandder_dump_action) {
                .name = "userLocationInfo",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ULI
        };
    dec->epslocation.members[2] =
        (struct wandder_dump_action) {
                .name = "gsmLocation",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->epslocation.members[3] =
        (struct wandder_dump_action) {
                .name = "umtsLocation",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->epslocation.members[4] =
        (struct wandder_dump_action) {
                .name = "olduserLocationInfo",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ULI
        };
    dec->epslocation.members[5] =
        (struct wandder_dump_action) {
                .name = "lastVisitedTAI",
                .descend = NULL,
                .interpretas = WANDDER_TAG_TAI
        };
    dec->epslocation.members[6] =
        (struct wandder_dump_action) {
                .name = "tAIlist",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->epslocation.members[7] =
        (struct wandder_dump_action) {
                .name = "threeGPP2Bsid",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->epslocation.members[8] =
        (struct wandder_dump_action) {
                .name = "civicAddress",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->epslocation.members[9] =
        (struct wandder_dump_action) {
                .name = "operatorSpecificInfo",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->epslocation.members[10] =
        (struct wandder_dump_action) {
                .name = "uELocationTimestamp",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };


    dec->additionalsignallingseq.membercount = 0;
    dec->additionalsignallingseq.members = NULL;
    dec->additionalsignallingseq.sequence =
        (struct wandder_dump_action) {
            .name = "additionalSignalling",
            .descend = &dec->additionalsignalling,
            .interpretas = WANDDER_TAG_NULL
        };

    dec->additionalsignalling.membercount = 1;
    ALLOC_MEMBERS(dec->additionalsignalling);
    dec->additionalsignalling.members[0] =
        (struct wandder_dump_action) {
                .name = "sipHeaderLine",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };

    dec->ipcccontents.membercount = 1;
    ALLOC_MEMBERS(dec->ipcccontents);
    dec->ipcccontents.members[0] =
        (struct wandder_dump_action) {
                .name = "iPPackets",
                .descend = NULL,
                .interpretas = WANDDER_TAG_IPPACKET
        };
    dec->ipcccontents.sequence = WANDDER_NOACTION;

    dec->ipcc.membercount = 2;
    ALLOC_MEMBERS(dec->ipcc);

    dec->ipcc.members[0] =
        (struct wandder_dump_action) {
                .name = "iPCCObjId",
                .descend = NULL,
                .interpretas = WANDDER_TAG_RELATIVEOID
        };
    dec->ipcc.members[1] =
        (struct wandder_dump_action) {
                .name = "iPCCContents",
                .descend = &dec->ipcccontents,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->ipcc.sequence = WANDDER_NOACTION;

    dec->epscc.membercount = 3;
    ALLOC_MEMBERS(dec->epscc);
    dec->epscc.members[0] = WANDDER_NOACTION;
    dec->epscc.members[1] =
        (struct wandder_dump_action) {
                .name = "uLIC-header",
                .descend = &dec->ulic_header,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->epscc.members[2] =
        (struct wandder_dump_action) {
                .name = "payload",
                .descend = NULL,
                .interpretas = WANDDER_TAG_IPPACKET
        };

    dec->ulic_header.membercount = 9;
    ALLOC_MEMBERS(dec->ulic_header);

    dec->ulic_header.members[0] =
        (struct wandder_dump_action) {
                .name = "hi3DomainId",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OID
        };
    dec->ulic_header.members[1] = WANDDER_NOACTION;
    dec->ulic_header.members[2] =
        (struct wandder_dump_action) {
                .name = "lIID",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->ulic_header.members[3] =
        (struct wandder_dump_action) {
                .name = "correlation-Number",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->ulic_header.members[4] =
        (struct wandder_dump_action) {
                .name = "timeStamp",
                .descend = &(dec->timestamp),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->ulic_header.members[5] =
        (struct wandder_dump_action) {
                .name = "sequence-number",
                .descend = NULL,
                .interpretas = WANDDER_TAG_INTEGER
        };
    dec->ulic_header.members[6] =
        (struct wandder_dump_action) {
                .name = "t-PDU-direction",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    // TODO nationalHI3ASN1Parameters
    dec->ulic_header.members[7] = WANDDER_NOACTION;
    dec->ulic_header.members[8] =
        (struct wandder_dump_action) {
                .name = "ice-type",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };

    dec->ipmmcc.membercount = 5;
    ALLOC_MEMBERS(dec->ipmmcc);

    dec->ipmmcc.members[0] =
        (struct wandder_dump_action) {
                .name = "iPMMCCObjId",
                .descend = NULL,
                .interpretas = WANDDER_TAG_RELATIVEOID
        };
    dec->ipmmcc.members[1] =
        (struct wandder_dump_action) {
                .name = "mMCCContents",
                .descend = NULL,
                .interpretas = WANDDER_TAG_IPPACKET
        };
    dec->ipmmcc.members[2] =
        (struct wandder_dump_action) {
                .name = "frameType",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->ipmmcc.members[3] =
        (struct wandder_dump_action) {
                .name = "streamIdentifier",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->ipmmcc.members[4] =
        (struct wandder_dump_action) {
                .name = "mMCCprotocol",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };



    dec->netelid.membercount = 6;
    ALLOC_MEMBERS(dec->netelid);

    dec->netelid.members[0] = WANDDER_NOACTION;
    dec->netelid.members[1] =
        (struct wandder_dump_action) {
                .name = "e164-Format",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->netelid.members[2] =
        (struct wandder_dump_action) {
                .name = "x25-Format",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->netelid.members[3] =
        (struct wandder_dump_action) {
                .name = "iP-Format",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->netelid.members[4] =
        (struct wandder_dump_action) {
                .name = "dNS-Format",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->netelid.members[5] =        // TODO
        (struct wandder_dump_action) {
                .name = "iP-Address",
                .descend = &dec->ipaddress,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->netelid.sequence = WANDDER_NOACTION;

    dec->root.membercount = 0;
    dec->root.members = NULL;
    dec->root.sequence =
        (struct wandder_dump_action) {
                .name = "pS-PDU",
                .descend = &dec->pspdu,
                .interpretas = WANDDER_TAG_NULL
        };

    dec->linetid.membercount = 3;
    ALLOC_MEMBERS(dec->linetid);
    dec->linetid.members[0] =
        (struct wandder_dump_action) {
                .name = "operatorIdentifier",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->linetid.members[1] =
        (struct wandder_dump_action) {
                .name = "networkElementIdentifier",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->linetid.members[2] =
        (struct wandder_dump_action) {
                .name = "eTSI671NEID",
                .descend = &dec->netelid,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->linetid.sequence = WANDDER_NOACTION;

    dec->networkidentifier.membercount = 2;
    ALLOC_MEMBERS(dec->networkidentifier);
    dec->networkidentifier.members[0] =
        (struct wandder_dump_action) {
                .name = "operator-Identifier",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->networkidentifier.members[1] =
        (struct wandder_dump_action) {
                .name = "network-Element-Identifier",
                .descend = &(dec->netelid),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->networkidentifier.sequence = WANDDER_NOACTION;

    dec->hi2op_cid.membercount = 2;
    ALLOC_MEMBERS(dec->hi2op_cid);
    dec->hi2op_cid.members[0] =
        (struct wandder_dump_action) {
                .name = "communication-Identity-Number",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->hi2op_cid.members[1] =
        (struct wandder_dump_action) {
                .name = "network-Identifier",
                .descend = &(dec->hi2op_netid),
                .interpretas = WANDDER_TAG_NULL
        };

    dec->hi2op_netid.membercount = 2;
    ALLOC_MEMBERS(dec->hi2op_netid);
    dec->hi2op_netid.members[0] =
        (struct wandder_dump_action) {
                .name = "operator-Identifier",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->hi2op_netid.members[1] =
        (struct wandder_dump_action) {
                .name = "network-Element-Identifier",
                .descend = &(dec->netelid),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->hi2op_netid.sequence = WANDDER_NOACTION;

    dec->cid.membercount = 3;
    ALLOC_MEMBERS(dec->cid);
    dec->cid.members[0] =
        (struct wandder_dump_action) {
                .name = "networkIdentifier",
                .descend = &dec->linetid,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->cid.members[1] =
        (struct wandder_dump_action) {
                .name = "communicationIdentityNumber",
                .descend = NULL,
                .interpretas = WANDDER_TAG_INTEGER
        };
    dec->cid.members[2] =
        (struct wandder_dump_action) {
                .name = "deliveryCountryCode",
                .descend = NULL,
                .interpretas = WANDDER_TAG_PRINTABLE
        };
    dec->cid.sequence = WANDDER_NOACTION;

    dec->msts.membercount = 2;
    ALLOC_MEMBERS(dec->msts);
    dec->msts.members[0] =
        (struct wandder_dump_action) {
                .name = "seconds",
                .descend = NULL,
                .interpretas = WANDDER_TAG_INTEGER
        };
    dec->msts.members[1] =
        (struct wandder_dump_action) {
                .name = "microSeconds",
                .descend = NULL,
                .interpretas = WANDDER_TAG_INTEGER
        };
    dec->msts.sequence = WANDDER_NOACTION;

    dec->cccontents.membercount = 19;
    ALLOC_MEMBERS(dec->cccontents);
    dec->cccontents.members[0] = WANDDER_NOACTION;
    dec->cccontents.members[1] =     // TODO
        (struct wandder_dump_action) {
                .name = "emailCC",
                .descend = &(dec->emailcc),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->cccontents.members[2] =
        (struct wandder_dump_action) {
                .name = "iPCC",
                .descend = &dec->ipcc,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->cccontents.members[3] = WANDDER_NOACTION;
    dec->cccontents.members[4] =
        (struct wandder_dump_action) {
                .name = "uMTSCC",
                .descend = NULL,
                .interpretas = WANDDER_TAG_IPPACKET
        };
    dec->cccontents.members[5] = WANDDER_NOACTION;
    dec->cccontents.members[6] = WANDDER_NOACTION;
    dec->cccontents.members[7] = WANDDER_NOACTION;
    dec->cccontents.members[8] = WANDDER_NOACTION;
    dec->cccontents.members[9] = WANDDER_NOACTION;
    dec->cccontents.members[10] = WANDDER_NOACTION;
    dec->cccontents.members[11] = WANDDER_NOACTION;
    dec->cccontents.members[12] =
        (struct wandder_dump_action) {
                .name = "iPMMCC",
                .descend = &dec->ipmmcc,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->cccontents.members[13] = WANDDER_NOACTION;
    dec->cccontents.members[14] = WANDDER_NOACTION;
    dec->cccontents.members[15] = WANDDER_NOACTION;
    dec->cccontents.members[16] = WANDDER_NOACTION;
    dec->cccontents.members[17] =
        (struct wandder_dump_action) {
                .name = "ePSCC",
                .descend = &dec->epscc,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->cccontents.members[18] = WANDDER_NOACTION;
    dec->cccontents.sequence = WANDDER_NOACTION;

    dec->ccpayload.membercount = 5;
    ALLOC_MEMBERS(dec->ccpayload);
    dec->ccpayload.members[0] =
        (struct wandder_dump_action) {
                .name = "payloadDirection",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->ccpayload.members[1] =
        (struct wandder_dump_action) {
                .name = "timeStamp",
                .descend = NULL,
                .interpretas = WANDDER_TAG_GENERALTIME
        };
    dec->ccpayload.members[2] =
        (struct wandder_dump_action) {
                .name = "cCContents",
                .descend = &dec->cccontents,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->ccpayload.members[3] =
        (struct wandder_dump_action) {
                .name = "microSecondTimestamp",
                .descend = &dec->msts,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->ccpayload.members[4] =
        (struct wandder_dump_action) {
                .name = "timeStampQualifier",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->ccpayload.sequence = WANDDER_NOACTION;

    dec->ccpayloadseq.membercount = 0;
    dec->ccpayloadseq.members = NULL;
    dec->ccpayloadseq.sequence =
        (struct wandder_dump_action) {
                .name = "CCPayload",
                .descend = &dec->ccpayload,
                .interpretas = WANDDER_TAG_NULL
        };

    dec->operatorleamessage.membercount = 2;
    ALLOC_MEMBERS(dec->operatorleamessage);
    dec->operatorleamessage.members[0] =
        (struct wandder_dump_action) {
                .name = "messagePriority",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->operatorleamessage.members[1] =
        (struct wandder_dump_action) {
                .name = "message",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };

    dec->integritycheck.membercount = 5;
    ALLOC_MEMBERS(dec->integritycheck);
    dec->integritycheck.members[0] =
        (struct wandder_dump_action) {
                .name = "includedSequenceNumbers",
                .descend = NULL,
                .interpretas = WANDDER_TAG_INTEGER_SEQUENCE
        };
    dec->integritycheck.members[1] =
        (struct wandder_dump_action) {
                .name = "checkType",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->integritycheck.members[2] =
        (struct wandder_dump_action) {
                .name = "dataType",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->integritycheck.members[3] =
        (struct wandder_dump_action) {
                .name = "checkValue",
                .descend = NULL,
                .interpretas = WANDDER_TAG_HEX_BYTES
        };
    dec->integritycheck.members[4] =
        (struct wandder_dump_action) {
                .name = "hashAlgorithm",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };

    dec->option.membercount = 1;
    ALLOC_MEMBERS(dec->option);
    dec->option.members[0] =
        (struct wandder_dump_action) {
                .name = "pDUAcknowledgement",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };


    dec->optionseq.membercount = 0;
    dec->optionseq.members = NULL;
    dec->optionseq.sequence =
        (struct wandder_dump_action) {
                .name = "Option",
                .descend = &(dec->option),
                .interpretas = WANDDER_TAG_NULL
        };

    dec->optionreq.membercount = 1;
    ALLOC_MEMBERS(dec->optionreq);
    dec->optionreq.members[0] =
        (struct wandder_dump_action) {
                .name = "requestedOptions",
                .descend = &(dec->optionseq),
                .interpretas = WANDDER_TAG_NULL
        };

    dec->optionresp.membercount = 2;
    ALLOC_MEMBERS(dec->optionresp);
    dec->optionresp.members[0] =
        (struct wandder_dump_action) {
                .name = "acceptedOptions",
                .descend = &(dec->optionseq),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->optionresp.members[1] =
        (struct wandder_dump_action) {
                .name = "declinedOptions",
                .descend = &(dec->optionseq),
                .interpretas = WANDDER_TAG_NULL
        };

    dec->hi1notification.membercount = 7;
    ALLOC_MEMBERS(dec->hi1notification);
    dec->hi1notification.members[0] =
        (struct wandder_dump_action) {
                .name = "domainID",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OID
        };
    dec->hi1notification.members[1] =
        (struct wandder_dump_action) {
                .name = "lawfulInterceptionIdentifier",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->hi1notification.members[2] =
        (struct wandder_dump_action) {
                .name = "communicationIdentifier",
                .descend = &(dec->hi2op_cid),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->hi1notification.members[3] =
        (struct wandder_dump_action) {
                .name = "timeStamp",
                .descend = &(dec->timestamp),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->hi1notification.members[4] = WANDDER_NOACTION;
    dec->hi1notification.members[5] =
        (struct wandder_dump_action) {
                .name = "national-HI1-ASN1parameters",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->hi1notification.members[6] =
        (struct wandder_dump_action) {
                .name = "target-Information",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };

    dec->hi1operation.membercount = 6;
    ALLOC_MEMBERS(dec->hi1operation);
    dec->hi1operation.members[0] = WANDDER_NOACTION;
    dec->hi1operation.members[1] =
        (struct wandder_dump_action) {
                .name = "liActivated",
                .descend = &(dec->hi1notification),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->hi1operation.members[2] =
        (struct wandder_dump_action) {
                .name = "liDeactivated",
                .descend = &(dec->hi1notification),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->hi1operation.members[3] =
        (struct wandder_dump_action) {
                .name = "liModified",
                .descend = &(dec->hi1notification),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->hi1operation.members[4] =
        (struct wandder_dump_action) {
                .name = "alarams-indicator",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->hi1operation.members[5] =
        (struct wandder_dump_action) {
                .name = "national-HI1-ASN1parameters",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };


    dec->tripayload.membercount = 14;
    ALLOC_MEMBERS(dec->tripayload);
    dec->tripayload.members[0] =
        (struct wandder_dump_action) {
                .name = "integrityCheck",
                .descend = &(dec->integritycheck),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->tripayload.members[1] =
        (struct wandder_dump_action) {
                .name = "testPDU",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->tripayload.members[2] =
        (struct wandder_dump_action) {
                .name = "paddingPDU",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->tripayload.members[3] =
        (struct wandder_dump_action) {
                .name = "keep-alive",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->tripayload.members[4] =
        (struct wandder_dump_action) {
                .name = "keep-aliveResponse",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->tripayload.members[5] =
        (struct wandder_dump_action) {
                .name = "firstSegmentFlag",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->tripayload.members[6] =
        (struct wandder_dump_action) {
                .name = "lastSegmentFlag",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->tripayload.members[7] =
        (struct wandder_dump_action) {
                .name = "cINReset",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->tripayload.members[8] =
        (struct wandder_dump_action) {
                .name = "operatorLeaMessage",
                .descend = &(dec->operatorleamessage),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->tripayload.members[9] =
        (struct wandder_dump_action) {
                .name = "optionRequest",
                .descend = &(dec->optionreq),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->tripayload.members[10] =
        (struct wandder_dump_action) {
                .name = "optionResponse",
                .descend = &(dec->optionresp),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->tripayload.members[11] =
        (struct wandder_dump_action) {
                .name = "optionComplete",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->tripayload.members[12] =
        (struct wandder_dump_action) {
                .name = "pDUAcknowledgementRequest",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->tripayload.members[13] =
        (struct wandder_dump_action) {
                .name = "pDUAcknowledgementResponse",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };


    dec->ipiriid.membercount = 3;
    ALLOC_MEMBERS(dec->ipiriid);
    dec->ipiriid.members[0] =
        (struct wandder_dump_action) {
                .name = "printableIDType",
                .descend = NULL,
                .interpretas = WANDDER_TAG_UTF8STR
        };
    dec->ipiriid.members[1] =
        (struct wandder_dump_action) {
                .name = "macAddressType",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->ipiriid.members[2] =
        (struct wandder_dump_action) {
                .name = "ipAddressType",
                .descend = &dec->ipaddress,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->ipiriid.sequence = WANDDER_NOACTION;

    dec->gprsparams.membercount = 6;
    ALLOC_MEMBERS(dec->gprsparams);
    dec->gprsparams.sequence = WANDDER_NOACTION;

    dec->gprsparams.members[0] = WANDDER_NOACTION;
    dec->gprsparams.members[1] =
        (struct wandder_dump_action) {
                .name = "pDP-address-allocated-to-the-target",
                .descend = &(dec->datanodeaddress),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->gprsparams.members[2] =
        (struct wandder_dump_action) {
                .name = "aPN",
                .descend = NULL,
                .interpretas = WANDDER_TAG_DOMAIN_NAME
        };
    dec->gprsparams.members[3] =
        (struct wandder_dump_action) {
                .name = "pDP-type",
                .descend = NULL,
                .interpretas = WANDDER_TAG_HEX_BYTES
        };
    dec->gprsparams.members[4] =
        (struct wandder_dump_action) {
                .name = "nSAPI",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->gprsparams.members[5] =
        (struct wandder_dump_action) {
                .name = "additionalIPaddress",
                .descend = &(dec->datanodeaddress),
                .interpretas = WANDDER_TAG_NULL
        };

    dec->servicesdatainfo.membercount = 2;
    ALLOC_MEMBERS(dec->servicesdatainfo)
    dec->servicesdatainfo.sequence = WANDDER_NOACTION;

    dec->servicesdatainfo.members[0] = WANDDER_NOACTION;
    dec->servicesdatainfo.members[1] =
        (struct wandder_dump_action) {
                .name = "gPRS-parameters",
                .descend = &dec->gprsparams,
                .interpretas = WANDDER_TAG_NULL
        };


    dec->partyidentity.membercount = 12;
    ALLOC_MEMBERS(dec->partyidentity);
    dec->partyidentity.sequence = WANDDER_NOACTION;

    dec->partyidentity.members[0] = WANDDER_NOACTION;
    dec->partyidentity.members[1] =
        (struct wandder_dump_action) {
                .name = "imei",
                .descend = NULL,
                .interpretas = WANDDER_TAG_3G_IMEI
        };
    dec->partyidentity.members[2] = WANDDER_NOACTION;
    dec->partyidentity.members[3] =
        (struct wandder_dump_action) {
                .name = "imsi",
                .descend = NULL,
                .interpretas = WANDDER_TAG_3G_IMEI
        };
    dec->partyidentity.members[4] = WANDDER_NOACTION;
    dec->partyidentity.members[5] = WANDDER_NOACTION;
    dec->partyidentity.members[6] =
        (struct wandder_dump_action) {
                .name = "msISDN",
                .descend = NULL,
                .interpretas = WANDDER_TAG_3G_IMEI
        };
    dec->partyidentity.members[7] =
        (struct wandder_dump_action) {
                .name = "e164-Format",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->partyidentity.members[8] =
        (struct wandder_dump_action) {
                .name = "sip-uri",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->partyidentity.members[9] =
        (struct wandder_dump_action) {
                .name = "tel-uri",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->partyidentity.members[10] =
        (struct wandder_dump_action) {
                .name = "x-3GPP-Asserted-Identity",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->partyidentity.members[11] =
        (struct wandder_dump_action) {
                .name = "xUI",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };


    dec->partyinfo.membercount = 5;
    ALLOC_MEMBERS(dec->partyinfo);
    dec->partyinfo.sequence = WANDDER_NOACTION;

    dec->partyinfo.members[0] =
        (struct wandder_dump_action) {
                .name = "party-Qualifier",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->partyinfo.members[1] =
        (struct wandder_dump_action) {
                .name = "partyIdentity",
                .descend = &dec->partyidentity,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->partyinfo.members[2] = WANDDER_NOACTION;
    dec->partyinfo.members[3] = WANDDER_NOACTION;
    dec->partyinfo.members[4] =
        (struct wandder_dump_action) {
                .name = "services-Data-Information",
                .descend = &dec->servicesdatainfo,
                .interpretas = WANDDER_TAG_NULL
        };


    dec->location.membercount = 14;
    ALLOC_MEMBERS(dec->location);
    dec->location.sequence = WANDDER_NOACTION;

    dec->location.members[0] = WANDDER_NOACTION;
    dec->location.members[1] =
        (struct wandder_dump_action) {
                .name = "e164-Number",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->location.members[2] =
        (struct wandder_dump_action) {
                .name = "globalCellID",
                .descend = NULL,
                .interpretas = WANDDER_TAG_CGI
        };
    dec->location.members[3] = WANDDER_NOACTION;
    dec->location.members[4] =
        (struct wandder_dump_action) {
                .name = "rAI",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->location.members[5] = WANDDER_NOACTION;
    dec->location.members[6] = WANDDER_NOACTION;
    dec->location.members[7] =
        (struct wandder_dump_action) {
                .name = "sAI",
                .descend = NULL,
                .interpretas = WANDDER_TAG_SAI
        };
    dec->location.members[8] =
        (struct wandder_dump_action) {
                .name = "oldRAI",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->location.members[9] =
        (struct wandder_dump_action) {
                .name = "tAI",
                .descend = NULL,
                .interpretas = WANDDER_TAG_TAI
        };
    dec->location.members[10] =
        (struct wandder_dump_action) {
                .name = "eCGI",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ECGI
        };
    dec->location.members[11] = WANDDER_NOACTION;
    dec->location.members[12] =
        (struct wandder_dump_action) {
                .name = "operatorSpecificInfo",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->location.members[13] =
        (struct wandder_dump_action) {
                .name = "uELocationTimestamp",
                .descend = &dec->timestamp,
                .interpretas = WANDDER_TAG_NULL
        };

    dec->umtsqos.membercount = 3;
    ALLOC_MEMBERS(dec->umtsqos);
    dec->umtsqos.sequence = WANDDER_NOACTION;

    dec->umtsqos.members[0] = WANDDER_NOACTION;
    dec->umtsqos.members[1] =
        (struct wandder_dump_action) {
                .name = "qosMobileRadio",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->umtsqos.members[2] =
        (struct wandder_dump_action) {
                .name = "qosGn",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };

    dec->eps_protconfigoptions.membercount = 3;
    ALLOC_MEMBERS(dec->eps_protconfigoptions);
    dec->eps_protconfigoptions.sequence = WANDDER_NOACTION;

    dec->eps_protconfigoptions.members[0] = WANDDER_NOACTION;
    dec->eps_protconfigoptions.members[1] =
        (struct wandder_dump_action) {
                .name = "ueToNetwork",
                .descend = NULL,
                .interpretas = WANDDER_TAG_HEX_BYTES
        };
    dec->eps_protconfigoptions.members[2] =
        (struct wandder_dump_action) {
                .name = "networkToUe",
                .descend = NULL,
                .interpretas = WANDDER_TAG_HEX_BYTES
        };

    dec->eps_gtpv2_params.membercount = 36;
    ALLOC_MEMBERS(dec->eps_gtpv2_params);
    dec->eps_gtpv2_params.sequence = WANDDER_NOACTION;

    for (i = 0; i < dec->eps_gtpv2_params.membercount; i++) {
        dec->eps_gtpv2_params.members[i] = WANDDER_NOACTION;
    }

    dec->eps_gtpv2_params.members[1] =
        (struct wandder_dump_action) {
                .name = "pDNAddressAllocation",
                .descend = NULL,
                .interpretas = WANDDER_TAG_HEX_BYTES
        };

    dec->eps_gtpv2_params.members[2] =
        (struct wandder_dump_action) {
                .name = "aPN",
                .descend = NULL,
                .interpretas = WANDDER_TAG_DOMAIN_NAME
        };

    dec->eps_gtpv2_params.members[3] =
        (struct wandder_dump_action) {
                .name = "protConfigOptions",
                .descend = &(dec->eps_protconfigoptions),
                .interpretas = WANDDER_TAG_NULL
        };

    dec->eps_gtpv2_params.members[4] =
        (struct wandder_dump_action) {
                .name = "attachType",
                .descend = NULL,
                .interpretas = WANDDER_TAG_EPS_ATTACH_TYPE
        };

    dec->eps_gtpv2_params.members[5] =
        (struct wandder_dump_action) {
                .name = "ePSBearerIdentity",
                .descend = NULL,
                .interpretas = WANDDER_TAG_HEX_BYTES
        };

    dec->eps_gtpv2_params.members[6] =
        (struct wandder_dump_action) {
                .name = "detachType",
                .descend = NULL,
                .interpretas = WANDDER_TAG_HEX_BYTES
        };

    dec->eps_gtpv2_params.members[7] =
        (struct wandder_dump_action) {
                .name = "rATType",
                .descend = NULL,
                .interpretas = WANDDER_TAG_EPS_RAT_TYPE
        };

    dec->eps_gtpv2_params.members[8] =
        (struct wandder_dump_action) {
                .name = "failedBearerActivationReason",
                .descend = NULL,
                .interpretas = WANDDER_TAG_EPS_CAUSE
        };

    dec->eps_gtpv2_params.members[9] =
        (struct wandder_dump_action) {
                .name = "ePSBearerQoS",
                .descend = NULL,
                .interpretas = WANDDER_TAG_HEX_BYTES
        };

    dec->eps_gtpv2_params.members[10] =
        (struct wandder_dump_action) {
                .name = "bearerActivationType",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };

    dec->eps_gtpv2_params.members[11] =
        (struct wandder_dump_action) {
                .name = "aPN-AMBR",
                .descend = NULL,
                .interpretas = WANDDER_TAG_EPS_APN_AMBR
        };

    dec->eps_gtpv2_params.members[13] =
        (struct wandder_dump_action) {
                .name = "linkedEPSBearerId",
                .descend = NULL,
                .interpretas = WANDDER_TAG_HEX_BYTES
        };

    dec->eps_gtpv2_params.members[16] =
        (struct wandder_dump_action) {
                .name = "failedBearerModificationReason",
                .descend = NULL,
                .interpretas = WANDDER_TAG_EPS_CAUSE
        };

    dec->eps_gtpv2_params.members[21] =
        (struct wandder_dump_action) {
                .name = "bearerDeactivationType",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };

    dec->eps_gtpv2_params.members[22] =
        (struct wandder_dump_action) {
                .name = "bearerDeactivationCause",
                .descend = NULL,
                .interpretas = WANDDER_TAG_EPS_CAUSE
        };

    dec->eps_gtpv2_params.members[23] =
        (struct wandder_dump_action) {
                .name = "ePSlocationOfTheTarget",
                .descend = &(dec->epslocation),
                .interpretas = WANDDER_TAG_NULL
        };

    dec->eps_gtpv2_params.members[24] =
        (struct wandder_dump_action) {
                .name = "pDNType",
                .descend = NULL,
                .interpretas = WANDDER_TAG_EPS_PDN_TYPE
        };


    /* TODO eps_gtpv2_params.members */

    /* Most of these are unused */
    dec->epsiri_params.membercount = 256;
    ALLOC_MEMBERS(dec->epsiri_params);
    dec->epsiri_params.sequence = WANDDER_NOACTION;

    for (i = 0; i < dec->epsiri_params.membercount; i++) {
        dec->epsiri_params.members[i] = WANDDER_NOACTION;
    }

    dec->epsiri_params.members[0] =
        (struct wandder_dump_action) {
                .name = "hi2epsDomainId",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OID
        };

    dec->epsiri_params.members[1] =
        (struct wandder_dump_action) {
                .name = "lawfulInterceptionIdentifier",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };

    dec->epsiri_params.members[3] =
        (struct wandder_dump_action) {
                .name = "timeStamp",
                .descend = &dec->timestamp,
                .interpretas = WANDDER_TAG_NULL
        };

    dec->epsiri_params.members[4] =
        (struct wandder_dump_action) {
                .name = "initiator",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };

    dec->epsiri_params.members[8] =
        (struct wandder_dump_action) {
                .name = "locationOfTheTarget",
                .descend = &dec->location,
                .interpretas = WANDDER_TAG_NULL
        };

    dec->epsiri_params.members[9] =
        (struct wandder_dump_action) {
                .name = "partyInformation",
                .descend = &dec->partyinfo,
                .interpretas = WANDDER_TAG_NULL
        };

    dec->epsiri_params.members[13] =
        (struct wandder_dump_action) {
                .name = "serviceCenterAddress",
                .descend = &dec->partyinfo,
                .interpretas = WANDDER_TAG_NULL
        };

    dec->epsiri_params.members[18] =
        (struct wandder_dump_action) {
                .name = "ePSCorrelationNumber",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };

    dec->epsiri_params.members[20] =
        (struct wandder_dump_action) {
                .name = "ePSevent",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };

    dec->epsiri_params.members[21] =
        (struct wandder_dump_action) {
                .name = "sgsnAddress",
                .descend = &(dec->datanodeaddress),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->epsiri_params.members[22] =
        (struct wandder_dump_action) {
                .name = "gPRSOperationErrorCode",
                .descend = NULL,
                .interpretas = WANDDER_TAG_3G_SM_CAUSE
        };
    dec->epsiri_params.members[24] =
        (struct wandder_dump_action) {
                .name = "ggsnAddress",
                .descend = &(dec->datanodeaddress),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->epsiri_params.members[25] =
        (struct wandder_dump_action) {
                .name = "qOS",
                .descend = &(dec->umtsqos),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->epsiri_params.members[26] =
        (struct wandder_dump_action) {
                .name = "networkIdentifier",
                .descend = &(dec->networkidentifier),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->epsiri_params.members[27] =
        (struct wandder_dump_action) {
                .name = "sMSOriginatingAddress",
                .descend = &(dec->datanodeaddress),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->epsiri_params.members[28] =
        (struct wandder_dump_action) {
                .name = "sMSTerminatingAddress",
                .descend = &(dec->datanodeaddress),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->epsiri_params.members[29] =
        (struct wandder_dump_action) {
                .name = "iMSevent",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->epsiri_params.members[30] =
        (struct wandder_dump_action) {
                .name = "sIPMessage",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->epsiri_params.members[31] =
        (struct wandder_dump_action) {
                .name = "servingSGSN-number",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->epsiri_params.members[32] =
        (struct wandder_dump_action) {
                .name = "servingSGSN-address",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->epsiri_params.members[34] =
        (struct wandder_dump_action) {
                .name = "ldiEvent",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->epsiri_params.members[35] = WANDDER_NOACTION;      // correlation
    dec->epsiri_params.members[36] =
        (struct wandder_dump_action) {
                .name = "ePS-GTPV2-specificParameters",
                .descend = &(dec->eps_gtpv2_params),
                .interpretas = WANDDER_TAG_NULL
        };

    /* TODO the rest of these members -- OpenLI doesn't need them so
     * can't justify spending too much time on them right now...
     */



    dec->umtsiri_params.membercount = 60;
    ALLOC_MEMBERS(dec->umtsiri_params);
    dec->umtsiri_params.sequence = WANDDER_NOACTION;

    dec->umtsiri_params.members[0] =
        (struct wandder_dump_action) {
                .name = "hi2DomainId",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OID
        };
    dec->umtsiri_params.members[1] =
        (struct wandder_dump_action) {
                .name = "lawfulInterceptionIdentifier",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->umtsiri_params.members[2] = WANDDER_NOACTION;
    dec->umtsiri_params.members[3] =
        (struct wandder_dump_action) {
                .name = "timeStamp",
                .descend = &dec->timestamp,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->umtsiri_params.members[4] =
        (struct wandder_dump_action) {
                .name = "initiator",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->umtsiri_params.members[5] = WANDDER_NOACTION;
    dec->umtsiri_params.members[6] = WANDDER_NOACTION;
    dec->umtsiri_params.members[7] = WANDDER_NOACTION;
    dec->umtsiri_params.members[8] =
        (struct wandder_dump_action) {
                .name = "locationOfTheTarget",
                .descend = &dec->location,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->umtsiri_params.members[9] =
        (struct wandder_dump_action) {
                .name = "partyInformation",
                .descend = &dec->partyinfo,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->umtsiri_params.members[10] = WANDDER_NOACTION;
    dec->umtsiri_params.members[11] = WANDDER_NOACTION;
    dec->umtsiri_params.members[12] = WANDDER_NOACTION;
    dec->umtsiri_params.members[13] = WANDDER_NOACTION;
    dec->umtsiri_params.members[14] = WANDDER_NOACTION;
    dec->umtsiri_params.members[15] = WANDDER_NOACTION;
    dec->umtsiri_params.members[16] = WANDDER_NOACTION;
    dec->umtsiri_params.members[17] = WANDDER_NOACTION;
    dec->umtsiri_params.members[18] =
        (struct wandder_dump_action) {
                .name = "gPRSCorrelationNumber",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->umtsiri_params.members[19] = WANDDER_NOACTION;
    dec->umtsiri_params.members[20] =
        (struct wandder_dump_action) {
                .name = "gPRSevent",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->umtsiri_params.members[21] =
        (struct wandder_dump_action) {
                .name = "sgsnAddress",
                .descend = &(dec->datanodeaddress),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->umtsiri_params.members[22] =
        (struct wandder_dump_action) {
                .name = "gPRSOperationErrorCode",
                .descend = NULL,
                .interpretas = WANDDER_TAG_3G_SM_CAUSE
        };
    dec->umtsiri_params.members[23] =
        (struct wandder_dump_action) {
                .name = "iRIversion",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->umtsiri_params.members[24] =
        (struct wandder_dump_action) {
                .name = "ggsnAddress",
                .descend = &(dec->datanodeaddress),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->umtsiri_params.members[25] = WANDDER_NOACTION;
    dec->umtsiri_params.members[26] =
        (struct wandder_dump_action) {
                .name = "networkIdentifier",
                .descend = &(dec->networkidentifier),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->umtsiri_params.members[27] = WANDDER_NOACTION;
    dec->umtsiri_params.members[28] = WANDDER_NOACTION;
    dec->umtsiri_params.members[29] = WANDDER_NOACTION;
    dec->umtsiri_params.members[30] = WANDDER_NOACTION;
    dec->umtsiri_params.members[31] = WANDDER_NOACTION;
    dec->umtsiri_params.members[32] = WANDDER_NOACTION;
    dec->umtsiri_params.members[33] = WANDDER_NOACTION;
    dec->umtsiri_params.members[34] = WANDDER_NOACTION;
    dec->umtsiri_params.members[35] = WANDDER_NOACTION;
    dec->umtsiri_params.members[36] = WANDDER_NOACTION;
    dec->umtsiri_params.members[37] = WANDDER_NOACTION;
    dec->umtsiri_params.members[38] = WANDDER_NOACTION;
    dec->umtsiri_params.members[39] = WANDDER_NOACTION;
    dec->umtsiri_params.members[40] = WANDDER_NOACTION;
    dec->umtsiri_params.members[41] = WANDDER_NOACTION;
    dec->umtsiri_params.members[42] = WANDDER_NOACTION;
    dec->umtsiri_params.members[43] = WANDDER_NOACTION;
    dec->umtsiri_params.members[44] = WANDDER_NOACTION;
    dec->umtsiri_params.members[45] = WANDDER_NOACTION;
    dec->umtsiri_params.members[46] = WANDDER_NOACTION;
    dec->umtsiri_params.members[47] = WANDDER_NOACTION;
    dec->umtsiri_params.members[48] = WANDDER_NOACTION;
    dec->umtsiri_params.members[49] = WANDDER_NOACTION;
    dec->umtsiri_params.members[50] = WANDDER_NOACTION;
    dec->umtsiri_params.members[51] = WANDDER_NOACTION;
    dec->umtsiri_params.members[52] = WANDDER_NOACTION;
    dec->umtsiri_params.members[53] = WANDDER_NOACTION;
    dec->umtsiri_params.members[54] = WANDDER_NOACTION;
    dec->umtsiri_params.members[55] = WANDDER_NOACTION;
    dec->umtsiri_params.members[56] = WANDDER_NOACTION;
    dec->umtsiri_params.members[57] = WANDDER_NOACTION;
    dec->umtsiri_params.members[58] = WANDDER_NOACTION;
    dec->umtsiri_params.members[59] = WANDDER_NOACTION;

    dec->ipiricontents.membercount = 24;
    ALLOC_MEMBERS(dec->ipiricontents);
    dec->ipiricontents.members[0] =
        (struct wandder_dump_action) {
                .name = "accessEventType",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->ipiricontents.members[1] =
        (struct wandder_dump_action) {
                .name = "targetUsername",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->ipiricontents.members[2] =
        (struct wandder_dump_action) {
                .name = "internetAccessType",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->ipiricontents.members[3] =
        (struct wandder_dump_action) {
                .name = "iPVersion",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->ipiricontents.members[4] =
        (struct wandder_dump_action) {
                .name = "targetIPAddress",
                .descend = &dec->ipaddress,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->ipiricontents.members[5] =
        (struct wandder_dump_action) {
                .name = "targetNetworkID",
                .descend = NULL,
                .interpretas = WANDDER_TAG_UTF8STR
        };
    dec->ipiricontents.members[6] =
        (struct wandder_dump_action) {
                .name = "targetCPEID",
                .descend = NULL,
                .interpretas = WANDDER_TAG_UTF8STR
        };
    dec->ipiricontents.members[7] =
        (struct wandder_dump_action) {
                .name = "targetLocation",
                .descend = NULL,
                .interpretas = WANDDER_TAG_UTF8STR
        };
    dec->ipiricontents.members[8] =
        (struct wandder_dump_action) {
                .name = "pOPPortNumber",
                .descend = NULL,
                .interpretas = WANDDER_TAG_INTEGER
        };
    dec->ipiricontents.members[9] =
        (struct wandder_dump_action) {
                .name = "callBackNumber",
                .descend = NULL,
                .interpretas = WANDDER_TAG_UTF8STR
        };
    dec->ipiricontents.members[10] =
        (struct wandder_dump_action) {
                .name = "startTime",
                .descend = NULL,
                .interpretas = WANDDER_TAG_GENERALTIME
        };
    dec->ipiricontents.members[11] =
        (struct wandder_dump_action) {
                .name = "endTime",
                .descend = NULL,
                .interpretas = WANDDER_TAG_GENERALTIME
        };
    dec->ipiricontents.members[12] =
        (struct wandder_dump_action) {
                .name = "endReason",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->ipiricontents.members[13] =
        (struct wandder_dump_action) {
                .name = "octetsReceived",
                .descend = NULL,
                .interpretas = WANDDER_TAG_INTEGER
        };
    dec->ipiricontents.members[14] =
        (struct wandder_dump_action) {
                .name = "octetsTransmitted",
                .descend = NULL,
                .interpretas = WANDDER_TAG_INTEGER
        };
    dec->ipiricontents.members[15] =
        (struct wandder_dump_action) {
                .name = "rawAAAData",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->ipiricontents.members[16] =
        (struct wandder_dump_action) {
                .name = "expectedEndTime",
                .descend = NULL,
                .interpretas = WANDDER_TAG_GENERALTIME
        };
    dec->ipiricontents.members[17] =
        (struct wandder_dump_action) {
                .name = "pOPPhoneNumber",
                .descend = NULL,
                .interpretas = WANDDER_TAG_UTF8STR
        };
    dec->ipiricontents.members[18] =
        (struct wandder_dump_action) {
                .name = "pOPIdentifier",
                .descend = &dec->ipiriid,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->ipiricontents.members[19] =
        (struct wandder_dump_action) {
                .name = "pOPIPAddress",
                .descend = &dec->ipaddress,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->ipiricontents.members[20] = WANDDER_NOACTION;   // TODO
    dec->ipiricontents.members[21] =
        (struct wandder_dump_action) {
                .name = "additionalIPAddress",
                .descend = &dec->ipaddress,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->ipiricontents.members[22] =
        (struct wandder_dump_action) {
                .name = "authenticationType",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->ipiricontents.members[23] = WANDDER_NOACTION;   // TODO
    dec->ipiricontents.sequence = WANDDER_NOACTION;

    dec->ipiri.membercount = 2;
    ALLOC_MEMBERS(dec->ipiri);
    dec->ipiri.members[0] =
        (struct wandder_dump_action) {
                .name = "iPIRIObjId",
                .descend = NULL,
                .interpretas = WANDDER_TAG_RELATIVEOID
        };
    dec->ipiri.members[1] =
        (struct wandder_dump_action) {
                .name = "iPIRIContents",
                .descend = &dec->ipiricontents,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->ipiri.sequence = WANDDER_NOACTION;

    dec->umtsiri.membercount = 4;
    ALLOC_MEMBERS(dec->umtsiri);
    dec->umtsiri.sequence =WANDDER_NOACTION;

    dec->umtsiri.members[0] =
        (struct wandder_dump_action) {
                .name = "iRI-Parameters",
                .descend = &(dec->umtsiri_params),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->umtsiri.members[1] = WANDDER_NOACTION;
    dec->umtsiri.members[2] = WANDDER_NOACTION;
    dec->umtsiri.members[3] = WANDDER_NOACTION;

    dec->epsiri.membercount = 2;
    ALLOC_MEMBERS(dec->epsiri);
    dec->epsiri.sequence = WANDDER_NOACTION;
    dec->epsiri.members[0] =
        (struct wandder_dump_action) {
                .name = "iRI-EPS-Parameters",
                .descend = &(dec->epsiri_params),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->epsiri.members[1] = WANDDER_NOACTION;      // TODO ?

    dec->emailcc.membercount = 3;
    ALLOC_MEMBERS(dec->emailcc);
    dec->emailcc.sequence =WANDDER_NOACTION;
    dec->emailcc.members[0] =
        (struct wandder_dump_action) {
                .name = "emailCCObjId",
                .descend = NULL,
                .interpretas = WANDDER_TAG_RELATIVEOID
        };
    dec->emailcc.members[1] =
        (struct wandder_dump_action) {
                .name = "email-Format",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->emailcc.members[2] =
        (struct wandder_dump_action) {
                .name = "email-Content",
                .descend = NULL,
                .interpretas = WANDDER_TAG_IPPACKET
        };

    dec->emailiri.membercount = 18;
    ALLOC_MEMBERS(dec->emailiri);
    dec->emailiri.members[0] =
        (struct wandder_dump_action) {
                .name = "emailIRIObjId",
                .descend = NULL,
                .interpretas = WANDDER_TAG_RELATIVEOID
        };
    dec->emailiri.members[1] =
        (struct wandder_dump_action) {
                .name = "eventType",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->emailiri.members[2] =
        (struct wandder_dump_action) {
                .name = "client-Address",
                .descend = (&dec->ipaddress),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->emailiri.members[3] =
        (struct wandder_dump_action) {
                .name = "server-Address",
                .descend = (&dec->ipaddress),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->emailiri.members[4] =
        (struct wandder_dump_action) {
                .name = "client-Port",
                .descend = NULL,
                .interpretas = WANDDER_TAG_INTEGER
        };
    dec->emailiri.members[5] =
        (struct wandder_dump_action) {
                .name = "server-Port",
                .descend = NULL,
                .interpretas = WANDDER_TAG_INTEGER
        };
    dec->emailiri.members[6] =
        (struct wandder_dump_action) {
                .name = "server-Octets-Sent",
                .descend = NULL,
                .interpretas = WANDDER_TAG_INTEGER
        };
    dec->emailiri.members[7] =
        (struct wandder_dump_action) {
                .name = "client-Octets-Sent",
                .descend = NULL,
                .interpretas = WANDDER_TAG_INTEGER
        };
    dec->emailiri.members[8] =
        (struct wandder_dump_action) {
                .name = "protocol-ID",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->emailiri.members[9] =
        (struct wandder_dump_action) {
                .name = "e-mail-Sender",
                .descend = NULL,
                .interpretas = WANDDER_TAG_UTF8STR
        };
    dec->emailiri.members[10] =
        (struct wandder_dump_action) {
                .name = "e-mail-Recipients",
                .descend = NULL,
                .interpretas = WANDDER_TAG_UTF8STR
        };
    dec->emailiri.members[11] =
        (struct wandder_dump_action) {
                .name = "status",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->emailiri.members[12] =
        (struct wandder_dump_action) {
                .name = "total-Recipient-Count",
                .descend = NULL,
                .interpretas = WANDDER_TAG_INTEGER
        };
    dec->emailiri.members[13] =
        (struct wandder_dump_action) {
                .name = "message-ID",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->emailiri.members[14] =
        (struct wandder_dump_action) {
                .name = "nationalParameter",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->emailiri.members[15] =
        (struct wandder_dump_action) {
                .name = "national-EM-ASN1parameters",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->emailiri.members[16] =
        (struct wandder_dump_action) {
                .name = "aAAInformation",
                .descend = &(dec->aaainformation),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->emailiri.members[17] =
        (struct wandder_dump_action) {
                .name = "e-mail-Sender-Validity",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->emailiri.sequence = WANDDER_NOACTION;

    dec->emailrecipients.membercount = 0;
    dec->emailrecipients.members = NULL;
    dec->emailrecipients.sequence =
        (struct wandder_dump_action) {
                .name = "recipient",
                .descend = NULL,
                .interpretas = WANDDER_TAG_UTF8STR
        };

    dec->aaainformation.membercount = 3;
    ALLOC_MEMBERS(dec->aaainformation);
    dec->aaainformation.members[0] =
        (struct wandder_dump_action) {
                .name = "pOP3AAAInformation",
                .descend = &(dec->pop3aaainformation),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->aaainformation.members[1] =
        (struct wandder_dump_action) {
                .name = "aSMTPAAAInformation",
                .descend = &(dec->asmtpaaainformation),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->aaainformation.members[2] =
        (struct wandder_dump_action) {
                .name = "iMAPAAAInformation",
                // not an error! uses the same sequence structure as pop3!
                .descend = &(dec->pop3aaainformation),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->aaainformation.sequence = WANDDER_NOACTION;

    dec->pop3aaainformation.membercount = 3;
    ALLOC_MEMBERS(dec->pop3aaainformation);
    dec->pop3aaainformation.members[0] =
        (struct wandder_dump_action) {
                .name = "username",
                .descend = NULL,
                .interpretas = WANDDER_TAG_UTF8STR
        };
    dec->pop3aaainformation.members[1] =
        (struct wandder_dump_action) {
                .name = "password",
                .descend = NULL,
                .interpretas = WANDDER_TAG_UTF8STR
        };
    dec->pop3aaainformation.members[2] =
        (struct wandder_dump_action) {
                .name = "aAAResult",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->pop3aaainformation.sequence = WANDDER_NOACTION;

    dec->asmtpaaainformation.membercount = 5;
    ALLOC_MEMBERS(dec->asmtpaaainformation);
    dec->asmtpaaainformation.members[0] =
        (struct wandder_dump_action) {
                .name = "username",
                .descend = NULL,
                .interpretas = WANDDER_TAG_UTF8STR
        };
    dec->asmtpaaainformation.members[1] =
        (struct wandder_dump_action) {
                .name = "authMethod",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->asmtpaaainformation.members[2] =
        (struct wandder_dump_action) {
                .name = "challenge",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->asmtpaaainformation.members[3] =
        (struct wandder_dump_action) {
                .name = "response",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->asmtpaaainformation.members[4] =
        (struct wandder_dump_action) {
                .name = "aAAResult",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->asmtpaaainformation.sequence = WANDDER_NOACTION;

    dec->iricontents.membercount = 20;
    ALLOC_MEMBERS(dec->iricontents);
    dec->iricontents.members[0] = WANDDER_NOACTION;
    dec->iricontents.members[1] =
        (struct wandder_dump_action) {
                .name = "emailIRI",
                .descend = &(dec->emailiri),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->iricontents.members[2] =
        (struct wandder_dump_action) {
                .name = "iPIRI",
                .descend = &dec->ipiri,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->iricontents.members[3] = WANDDER_NOACTION;
    dec->iricontents.members[4] =
            (struct wandder_dump_action) {
                .name = "uMTSIRI",
                .descend = &dec->umtsiri,
                .interpretas = WANDDER_TAG_NULL
            };
    dec->iricontents.members[5] = WANDDER_NOACTION;
    dec->iricontents.members[6] = WANDDER_NOACTION;
    dec->iricontents.members[7] = WANDDER_NOACTION;
    dec->iricontents.members[8] = WANDDER_NOACTION;
    dec->iricontents.members[9] = WANDDER_NOACTION;
    dec->iricontents.members[10] = WANDDER_NOACTION;
    dec->iricontents.members[11] =
        (struct wandder_dump_action) {
                .name = "iPMMIRI",
                .descend = &dec->ipmmiri,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->iricontents.members[12] = WANDDER_NOACTION;
    dec->iricontents.members[13] = WANDDER_NOACTION;
    dec->iricontents.members[14] = WANDDER_NOACTION;
    dec->iricontents.members[15] =
        (struct wandder_dump_action) {
                .name = "ePSIRI",
                .descend = &dec->epsiri,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->iricontents.members[16] = WANDDER_NOACTION;
    dec->iricontents.members[17] = WANDDER_NOACTION;
    dec->iricontents.members[18] = WANDDER_NOACTION;
    dec->iricontents.members[19] = WANDDER_NOACTION;
    dec->iricontents.sequence = WANDDER_NOACTION;


    dec->iripayload.membercount = 5;
    ALLOC_MEMBERS(dec->iripayload);
    dec->iripayload.members[0] =
        (struct wandder_dump_action) {
                .name = "iRIType",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->iripayload.members[1] =
        (struct wandder_dump_action) {
                .name = "timeStamp",
                .descend = NULL,
                .interpretas = WANDDER_TAG_GENERALTIME
        };
    dec->iripayload.members[2] =
        (struct wandder_dump_action) {
                .name = "iRIContents",
                .descend = &dec->iricontents,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->iripayload.members[3] =
        (struct wandder_dump_action) {
                .name = "microSecondTimestamp",
                .descend = &dec->msts,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->iripayload.members[4] =
        (struct wandder_dump_action) {
                .name = "timeStampQualifier",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    dec->iripayload.sequence = WANDDER_NOACTION;

    dec->iripayloadseq.membercount = 0;
    dec->iripayloadseq.members = NULL;
    dec->iripayloadseq.sequence =
        (struct wandder_dump_action) {
                .name = "IRIPayload",
                .descend = &dec->iripayload,
                .interpretas = WANDDER_TAG_NULL
        };

    dec->payload.membercount = 5;
    ALLOC_MEMBERS(dec->payload);
    dec->payload.sequence = WANDDER_NOACTION;
    dec->payload.members[0] =
        (struct wandder_dump_action) {
                .name = "iRIPayloadSequence",
                .descend = &dec->iripayloadseq,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->payload.members[1] =
        (struct wandder_dump_action) {
                .name = "cCPayloadSequence",
                .descend = &dec->ccpayloadseq,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->payload.members[2] =
        (struct wandder_dump_action) {
                .name = "tRIPayload",
                .descend = &(dec->tripayload),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->payload.members[3] =        // Not required
        (struct wandder_dump_action) {
                .name = "hI1-Operation",
                .descend = &(dec->hi1operation),
                .interpretas = WANDDER_TAG_NULL
        };
    dec->payload.members[4] =
        (struct wandder_dump_action) {
                .name = "encryptionContainer",
                .descend = &(dec->encryptioncontainer),
                .interpretas = WANDDER_TAG_NULL
        };
        
    /*
     * Handling of encrypted payload
     * WPvS, 04-05-2023
     *
    */

	dec->encryptioncontainer.membercount = 3;
	ALLOC_MEMBERS(dec->encryptioncontainer);
	dec->encryptioncontainer.sequence = WANDDER_NOACTION;
	dec->encryptioncontainer.members[0] = 
        (struct wandder_dump_action) {
                .name = "encryptionType",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    /* encrypted payload needs to be decrypted first, before descending into payload */
	dec->encryptioncontainer.members[1] =
        (struct wandder_dump_action) {
                .name = "encryptedPayload",
                .descend = &(dec->encryptedpayload),
                .interpretas = WANDDER_TAG_ENCRYPTED
        };
	dec->encryptioncontainer.members[2] = 
        (struct wandder_dump_action) {
                .name = "encryptedPayloadType",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };

    dec->encryptedpayloadroot.membercount = 0;
    dec->encryptedpayloadroot.members = NULL;
    dec->encryptedpayloadroot.sequence =
        (struct wandder_dump_action) {
                .name = "encryptedPayload",
                .descend = &dec->encryptedpayload,
                .interpretas = WANDDER_TAG_NULL
        };

	dec->encryptedpayload.membercount = 2;
	ALLOC_MEMBERS(dec->encryptedpayload);
	dec->encryptedpayload.sequence = WANDDER_NOACTION;
	dec->encryptedpayload.members[0] = 
        (struct wandder_dump_action) {
                .name = "byteCounter",
                .descend = NULL,
                .interpretas = WANDDER_TAG_INTEGER
        };
	dec->encryptedpayload.members[1] = 
        (struct wandder_dump_action) {
                .name = "payload",
                .descend = &(dec->payload),
                .interpretas = WANDDER_TAG_NULL
        };
    
    /* End of encrypted payload, WPvS */

    dec->psheader.membercount = 9;
    ALLOC_MEMBERS(dec->psheader);
    dec->psheader.sequence = WANDDER_NOACTION;
    dec->psheader.members[0] =
        (struct wandder_dump_action) {
                .name = "li-psDomainId",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OID
        };
    dec->psheader.members[1] =
        (struct wandder_dump_action) {
                .name = "lawfulInterceptionIdentifier",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->psheader.members[2] =
        (struct wandder_dump_action) {
                .name = "authorizationCountryCode",
                .descend = NULL,
                .interpretas = WANDDER_TAG_PRINTABLE
        };
    dec->psheader.members[3] =
        (struct wandder_dump_action) {
                .name = "communicationIdentifier",
                .descend = &dec->cid,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->psheader.members[4] =
        (struct wandder_dump_action) {
                .name = "sequenceNumber",
                .descend = NULL,
                .interpretas = WANDDER_TAG_INTEGER
        };
    dec->psheader.members[5] =
        (struct wandder_dump_action) {
                .name = "timeStamp",
                .descend = NULL,
                .interpretas = WANDDER_TAG_GENERALTIME
        };
    dec->psheader.members[6] =
        (struct wandder_dump_action) {
                .name = "interceptionPointID",
                .descend = NULL,
                .interpretas = WANDDER_TAG_PRINTABLE
        };
    dec->psheader.members[7] =
        (struct wandder_dump_action) {
                .name = "microSecondTimeStamp",
                .descend = &dec->msts,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->psheader.members[8] =
        (struct wandder_dump_action) {
                .name = "timeStampQualifier",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };


    dec->pspdu.membercount = 3;
    ALLOC_MEMBERS(dec->pspdu);
    dec->pspdu.sequence = WANDDER_NOACTION;
    dec->pspdu.members[0] = WANDDER_NOACTION;
    dec->pspdu.members[1] =
        (struct wandder_dump_action) {
                .name = "PSHeader",
                .descend = &dec->psheader,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->pspdu.members[2] =
        (struct wandder_dump_action) {
                .name = "Payload",
                .descend = &dec->payload,
                .interpretas = WANDDER_TAG_NULL
        };
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
