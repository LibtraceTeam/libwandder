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

#define INITIAL_ENCODER_SIZE 2048
#define INCREMENT_ENCODER_SIZE 512

const uint8_t etsi_lipsdomainid[8] = {
        0x00, 0x04, 0x00, 0x02, 0x02, 0x05, 0x01, 0x11};

uint8_t etsi_ipccoid[4] = {0x05, 0x03, 0x0a, 0x02};
uint8_t etsi_ipirioid[4] = {0x05, 0x03, 0x0a, 0x01};
uint8_t etsi_ipmmccoid[4] = {0x05, 0x05, 0x06, 0x02};
uint8_t etsi_ipmmirioid[4] = {0x05, 0x05, 0x06, 0x01};
uint8_t etsi_umtsirioid[9] = {0x00, 0x04, 0x00, 0x02, 0x02, 0x04, 0x01, 0x0f, 0x05};

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
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len);
static char *stringify_tai(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len);
static char *stringify_cgi(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len);
static char *stringify_ecgi(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len);
static char *stringify_sai(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len);

#define QUICK_DECODE(fail) \
    ret = wandder_decode_next(etsidec->dec); \
    if (ret <= 0) { \
        return fail; \
    } \
    ident = wandder_get_identifier(etsidec->dec);


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

    return etsidec;
}

uint8_t wandder_etsili_get_cc_format(wandder_etsispec_t *etsidec) {
    return etsidec->ccformat;
}

static uint8_t wandder_etsili_get_email_format(wandder_etsispec_t *etsidec) {
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
    wandder_reset_decoder(etsidec->dec);
    tgt.parent = &etsidec->emailcc;
    tgt.itemid = 1;
    tgt.found = false;

    if (wandder_search_items(etsidec->dec, 0, &(etsidec->root), &tgt, 1,
                &found, 1) > 0) {
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
    if (etsidec->decstate) {
        free_wandder_decoder(etsidec->dec);
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

    tv.tv_sec = 0;
    tv.tv_usec = 0;
    if (etsidec->decstate == 0) {
        fprintf(stderr, "No buffer attached to this decoder -- please call"
                "wandder_attach_etsili_buffer() first!\n");
        return tv;
    }

    /* Find PSHeader */
    wandder_reset_decoder(etsidec->dec);
    QUICK_DECODE(tv);
    QUICK_DECODE(tv);

    /* dec->current should be pointing right at PSHeader */
    if (ident != 1) {
        return tv;
    }

    if ((ret = wandder_decode_sequence_until(etsidec->dec, 5)) < 0) {
        return tv;
    }

    if (ret == 1) {
        tv = wandder_generalizedts_to_timeval(etsidec->dec,
                (char *)(wandder_get_itemptr(etsidec->dec)),
                wandder_get_itemlen(etsidec->dec));
        return tv;
    } else if ((ret = wandder_decode_sequence_until(etsidec->dec, 7)) < 0) {
        return tv;
    }

    if (ret == 1) {
        QUICK_DECODE(tv);
        tv.tv_sec = wandder_get_integer_value(etsidec->dec->current, NULL);
        QUICK_DECODE(tv);
        tv.tv_usec = wandder_get_integer_value(etsidec->dec->current, NULL);
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

char *wandder_etsili_get_next_fieldstr(wandder_etsispec_t *etsidec, char *space,
        int spacelen) {
    uint32_t ident;
    wandder_dumper_t *curr = NULL;
    char valstr[2048];

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

    if (wandder_decode_next(etsidec->dec) <= 0) {
        return NULL;
    }


    while (wandder_get_level(etsidec->dec) < etsidec->stack->current) {
        assert(etsidec->stack->current > 0);
        etsidec->stack->current --;
    }

    curr = etsidec->stack->stk[etsidec->stack->current];
    if (curr == NULL) {
        return NULL;
    }

    switch(wandder_get_class(etsidec->dec)) {

        case WANDDER_CLASS_CONTEXT_PRIMITIVE:
            ident = wandder_get_identifier(etsidec->dec);
            (etsidec->stack->atthislevel[etsidec->stack->current])++;

            if (curr == &(etsidec->emailcc) && ident == 1) {
                int64_t val;
                val = wandder_get_integer_value(etsidec->dec->current, NULL);

                if (val <= 255) {
                    etsidec->ccformat = (uint8_t) val;
                }
            }

            if (curr->members[ident].interpretas == WANDDER_TAG_IPPACKET) {
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
                if (stringify_ipaddress(etsidec, etsidec->dec->current, curr,
                        valstr, 2048) == NULL) {
                    fprintf(stderr, "Failed to interpret IP field %d:%d\n",
                            etsidec->stack->current, ident);
                    return NULL;
                }
            }

            else if (curr->members[ident].interpretas == WANDDER_TAG_ENUM) {
                if (interpret_enum(etsidec, etsidec->dec->current, curr,
                            valstr, 2048) == NULL) {
                    fprintf(stderr, "Failed to interpret enum field %d:%d\n",
                            etsidec->stack->current, ident);
                    return NULL;
                }
            }
            else if (curr->members[ident].interpretas == WANDDER_TAG_3G_IMEI) {
                if (stringify_3gimei(etsidec, etsidec->dec->current, curr,
                            valstr, 2048) == NULL) {
                    fprintf(stderr,
                            "Failed to interpret 3G IMEI-style field %d:%d\n",
                            etsidec->stack->current, ident);
                    return NULL;
                }
            }
            else if (curr->members[ident].interpretas ==
                    WANDDER_TAG_3G_SM_CAUSE) {
                if (stringify_3gcause(etsidec, etsidec->dec->current, curr,
                            valstr, 2048) == NULL) {
                    fprintf(stderr,
                            "Failed to interpret 3G SM-Cause field %d:%d\n",
                            etsidec->stack->current, ident);
                    return NULL;
                }
            }
            else if (curr->members[ident].interpretas == WANDDER_TAG_DOMAIN_NAME) {
                if (stringify_domain_name(etsidec, etsidec->dec->current, curr,
                            valstr, 2048) == NULL) {
                    fprintf(stderr,
                            "Failed to interpret domain name field %d:%d\n",
                            etsidec->stack->current, ident);
                    return NULL;
                }
            }
            else if (curr->members[ident].interpretas == WANDDER_TAG_HEX_BYTES) {
                if (stringify_bytes_as_hex(etsidec, etsidec->dec->current, curr,
                            valstr, 2048) == NULL) {
                    fprintf(stderr,
                            "Failed to interpret hex bytes field %d:%d\n",
                            etsidec->stack->current, ident);
                    return NULL;
                }
            }
            else if (curr->members[ident].interpretas == WANDDER_TAG_TAI) {
                if (stringify_tai(etsidec, etsidec->dec->current, curr,
                            valstr, 2048) == NULL) {
                    fprintf(stderr,
                            "Failed to interpret TAI field %d:%d\n",
                            etsidec->stack->current, ident);
                    return NULL;
                }
            }
            else if (curr->members[ident].interpretas == WANDDER_TAG_ECGI) {
                if (stringify_ecgi(etsidec, etsidec->dec->current, curr,
                            valstr, 2048) == NULL) {
                    fprintf(stderr,
                            "Failed to interpret ECGI field %d:%d\n",
                            etsidec->stack->current, ident);
                    return NULL;
                }
            }
            else if (curr->members[ident].interpretas == WANDDER_TAG_CGI) {
                if (stringify_cgi(etsidec, etsidec->dec->current, curr,
                            valstr, 2048) == NULL) {
                    fprintf(stderr,
                            "Failed to interpret CGI field %d:%d\n",
                            etsidec->stack->current, ident);
                    return NULL;
                }
            }
            else if (curr->members[ident].interpretas == WANDDER_TAG_SAI) {
                if (stringify_sai(etsidec, etsidec->dec->current, curr,
                            valstr, 2048) == NULL) {
                    fprintf(stderr,
                            "Failed to interpret SAI field %d:%d\n",
                            etsidec->stack->current, ident);
                    return NULL;
                }
            }
            else {
                if (!wandder_get_valuestr(etsidec->dec->current, valstr, 2048,
                        curr->members[ident].interpretas)) {
                    fprintf(stderr, "Failed to interpret field %d:%d\n",
                            etsidec->stack->current, ident);
                    return NULL;
                }
            }

            snprintf(space, spacelen, "%s: %s", curr->members[ident].name,
                    valstr);
            break;

        case WANDDER_CLASS_UNIVERSAL_PRIMITIVE:
            ident = (uint32_t)etsidec->stack->atthislevel[etsidec->stack->current];
            (etsidec->stack->atthislevel[etsidec->stack->current])++;
            if (!wandder_get_valuestr(etsidec->dec->current, valstr, 2048,
                    wandder_get_identifier(etsidec->dec))) {
                fprintf(stderr, "Failed to interpret standard field %d:%d\n",
                        etsidec->stack->current, ident);
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
            (etsidec->stack->atthislevel[etsidec->stack->current])++;
            push_stack(etsidec->stack, curr->sequence.descend);
            break;

        case WANDDER_CLASS_CONTEXT_CONSTRUCT:
            if (curr == NULL) {
                return NULL;
            }
            ident = wandder_get_identifier(etsidec->dec);
            (etsidec->stack->atthislevel[etsidec->stack->current])++;
            snprintf(space, spacelen, "%s:", curr->members[ident].name);
            push_stack(etsidec->stack, curr->members[ident].descend);
            break;
        default:
            return NULL;
    }

    return space;
}

wandder_decoder_t *wandder_get_etsili_base_decoder(wandder_etsispec_t *dec) {
    return (dec->dec);
}

uint8_t *wandder_etsili_get_cc_contents(wandder_etsispec_t *etsidec,
        uint32_t *len, char *name, int namelen) {
    uint8_t *vp = NULL;

    if (etsidec->decstate == 0) {
        fprintf(stderr, "No buffer attached to this decoder -- please call"
                "wandder_attach_etsili_buffer() first!\n");
        return NULL;
    }
    etsidec->ccformat = WANDDER_ETSILI_CC_FORMAT_UNKNOWN;

    /* Find IPCCContents or IPMMCCContents or UMTSCC or emailCC */
    wandder_reset_decoder(etsidec->dec);
    wandder_found_t *found = NULL;
    wandder_target_t cctgts[4];

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

    *len = 0;
    if (wandder_search_items(etsidec->dec, 0, &(etsidec->root), cctgts, 4,
                &found, 1) > 0) {
        *len = found->list[0].item->length;
        vp = found->list[0].item->valptr;

        if (found->list[0].targetid == 0) {
            strncpy(name, etsidec->ipcccontents.members[0].name, namelen);
            etsidec->ccformat = WANDDER_ETSILI_CC_FORMAT_IP;
        } else if (found->list[0].targetid == 1) {
            strncpy(name, etsidec->ipmmcc.members[1].name, namelen);
            etsidec->ccformat = WANDDER_ETSILI_CC_FORMAT_IP;
        } else if (found->list[0].targetid == 2) {
            strncpy(name, etsidec->cccontents.members[4].name, namelen);
            etsidec->ccformat = WANDDER_ETSILI_CC_FORMAT_IP;
        } else if (found->list[0].targetid == 3) {
            strncpy(name, etsidec->emailcc.members[2].name, namelen);
            wandder_etsili_get_email_format(etsidec);
        }
        wandder_free_found(found);
    }

    return vp;

}

uint8_t *wandder_etsili_get_iri_contents(wandder_etsispec_t *etsidec,
        uint32_t *len, uint8_t *ident, char *name, int namelen) {

    uint8_t *vp = NULL;

    if (etsidec->decstate == 0) {
        fprintf(stderr, "No buffer attached to this decoder -- please call"
                "wandder_attach_etsili_buffer() first!\n");
        return NULL;
    }
    wandder_reset_decoder(etsidec->dec);
    wandder_found_t *found = NULL;
    wandder_target_t iritgts[3];

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

    /* TODO H323 contents... */

    *len = 0;
    if (wandder_search_items(etsidec->dec, 0, &(etsidec->root), iritgts, 2,
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
        }
        wandder_free_found(found);
    }

    return vp;


}

uint32_t wandder_etsili_get_cin(wandder_etsispec_t *etsidec) {

    uint32_t ident;
    int ret;

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

int64_t wandder_etsili_get_sequence_number(wandder_etsispec_t *etsidec) {
    uint32_t ident;
    int64_t res;
    int ret;

    if (etsidec->decstate == 0) {
        fprintf(stderr, "No buffer attached to this decoder -- please call"
                "wandder_attach_etsili_buffer() first!\n");
        return -1;
    }

    wandder_reset_decoder(etsidec->dec);
    QUICK_DECODE(-1);
    QUICK_DECODE(-1);
    if (ident != 1) {
        return -1;
    }

    do {
        QUICK_DECODE(-1);
        if (wandder_get_class(etsidec->dec) == WANDDER_CLASS_CONTEXT_CONSTRUCT
                || wandder_get_class(etsidec->dec) ==
                        WANDDER_CLASS_UNIVERSAL_CONSTRUCT) {
            wandder_decode_skip(etsidec->dec);
        }
    } while (ident < 4);

    if (ident != 4) {
        return -1;
    }

    res = wandder_get_integer_value(etsidec->dec->current, NULL);
    return res;
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

static inline int stringify_lai(uint8_t *todecode, int decodelen,
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

static char *stringify_tai(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len) {

    char *nextwrite;
    int used = 0;
    char tac[24];

    memset(valstr, 0, len);

    used = stringify_lai(item->valptr + 1, item->length - 1, valstr, len);

    if (used == 0 || used >= len) {
        return NULL;
    }

    nextwrite = valstr + used;
    snprintf(tac, 24, "%u", ntohs(*((uint16_t *)(item->valptr + 4))));

    if (strlen(tac) > len - used) {
        return NULL;
    }

    memcpy(nextwrite, tac, strlen(tac));
    return valstr;
}

static char *stringify_ecgi(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len) {

    char *nextwrite;
    int used = 0;
    char eci[24];

    memset(valstr, 0, len);

    used = stringify_lai(item->valptr + 1, item->length - 1, valstr, len);

    if (used == 0 || used >= len) {
        return NULL;
    }

    nextwrite = valstr + used;
    snprintf(eci, 24, "%u", ntohl(*((uint32_t *)(item->valptr + 4))));

    if (strlen(eci) > len - used) {
        return NULL;
    }

    memcpy(nextwrite, eci, strlen(eci));
    return valstr;
}

static char *stringify_sai(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len) {

    char *nextwrite;
    int used = 0;
    char lac[24];
    char sac[24];

    memset(valstr, 0, len);

    used = stringify_lai(item->valptr, item->length, valstr, len);

    if (used == 0 || used >= len) {
        return NULL;
    }

    nextwrite = valstr + used;
    snprintf(lac, 24, "%u", ntohs(*((uint16_t *)(item->valptr + 3))));
    snprintf(sac, 24, "%u", ntohs(*((uint16_t *)(item->valptr + 5))));

    if (strlen(lac) + strlen(sac) + 1 > len - used) {
        return NULL;
    }

    memcpy(nextwrite, lac, strlen(lac));
    nextwrite += strlen(lac);

    *nextwrite = '-';
    nextwrite ++;

    memcpy(nextwrite, sac, strlen(sac));
    return valstr;
}


static char *stringify_cgi(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len) {

    char *nextwrite;
    int used = 0;
    char lac[24];
    char cellid[24];

    memset(valstr, 0, len);

    used = stringify_lai(item->valptr, item->length, valstr, len);

    if (used == 0 || used >= len) {
        return NULL;
    }

    nextwrite = valstr + used;
    snprintf(lac, 24, "%u", ntohs(*((uint16_t *)(item->valptr + 3))));
    snprintf(cellid, 24, "%u", ntohs(*((uint16_t *)(item->valptr + 5))));

    if (strlen(lac) + strlen(cellid) + 1 > len - used) {
        return NULL;
    }

    memcpy(nextwrite, lac, strlen(lac));
    nextwrite += strlen(lac);

    *nextwrite = '-';
    nextwrite ++;

    memcpy(nextwrite, cellid, strlen(cellid));
    return valstr;
}

static char *stringify_bytes_as_hex(wandder_etsispec_t *etsidec,
        wandder_item_t *item, wandder_dumper_t *curr, char *valstr, int len) {

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
                name = "SHA-1 Hash";
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

    else if (item->identifier == 4 && curr == &(etsidec->umtsiri_params)) {
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
    else if (item->identifier == 0 && curr == &(etsidec->encryptedpayload)) {
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
    }

    else if (item->identifier == 2 && curr == &(etsidec->encryptedpayload)) {
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
    }


    if (name != NULL) {
        snprintf(valstr, len, "%s", name);
        return name;
    }

    return NULL;
}

/*TODO: add encrypted payload type*/
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
    free(dec->datanodeaddress.members);
    free(dec->ipaddress.members);
    free(dec->ipcccontents.members);
    free(dec->ipmmcc.members);
    free(dec->ipcc.members);
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
    free(dec->emailrecipientsingle.members);
    free(dec->aaainformation.members);
    free(dec->pop3aaainformation.members);
    free(dec->asmtpaaainformation.members);
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

    dec->ipmmiri.membercount = 2;
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
    dec->ipmmiri.sequence = WANDDER_NOACTION;


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
    dec->cccontents.members[17] = WANDDER_NOACTION;
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

    dec->inclseqnos.membercount = 0;
    dec->inclseqnos.members = NULL;
    dec->inclseqnos.sequence =
        (struct wandder_dump_action) {
                .name = "sequenceNumber",
                .descend = NULL,
                .interpretas = WANDDER_TAG_INTEGER
        };

    dec->integritycheck.membercount = 4;
    ALLOC_MEMBERS(dec->integritycheck);
    dec->integritycheck.members[0] =
        (struct wandder_dump_action) {
                .name = "includedSequenceNumbers",
                .descend = &(dec->inclseqnos),
                .interpretas = WANDDER_TAG_NULL
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
                .interpretas = WANDDER_TAG_OCTETSTRING
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
                .descend = &(dec->emailrecipients),
                .interpretas = WANDDER_TAG_NULL
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
                .name = "E-mail-Address-List",
                .descend = &(dec->emailrecipientsingle),
                .interpretas = WANDDER_TAG_NULL
        };

    dec->emailrecipientsingle.membercount = 1;
    ALLOC_MEMBERS(dec->emailrecipientsingle);
    dec->emailrecipientsingle.members[0] =
        (struct wandder_dump_action) {
                .name = "recipient",
                .descend = NULL,
                .interpretas = WANDDER_TAG_UTF8STR
        };
    dec->emailrecipientsingle.sequence = WANDDER_NOACTION;

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

    dec->iricontents.membercount = 16;
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
    dec->iricontents.members[11] =   // TODO
        (struct wandder_dump_action) {
                .name = "iPMMIRI",
                .descend = &dec->ipmmiri,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->iricontents.members[12] = WANDDER_NOACTION;
    dec->iricontents.members[13] = WANDDER_NOACTION;
    dec->iricontents.members[14] = WANDDER_NOACTION;
    dec->iricontents.members[15] = WANDDER_NOACTION;
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
    dec->payload.members[0] =        // TODO
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
    dec->payload.members[2] =        // Not required
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
    dec->payload.members[4] =        // TODO?
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
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
/*
                .descend = &(dec->encryptedpayload),
                .interpretas = WANDDER_TAG_ENCRYPTED
*/
	dec->encryptioncontainer.members[2] = 
        (struct wandder_dump_action) {
                .name = "encryptedPayloadType",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
        
	dec->encryptedpayload.membercount = 2;
	ALLOC_MEMBERS(dec->encryptionpayload);
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
                .interpretas = WANDDER_TAG_ENUM
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

/////////////////////////////////start of BER code

static inline void encode_ipaddress(wandder_encoder_ber_t* enc_ber, 
        wandder_etsili_ipaddress_t *addr){

    uint32_t addrlen = 4;
    uint32_t iptype = addr->iptype;
    uint32_t assign = addr->assignment;
    uint32_t prefbits = addr->v6prefixlen;

    if (addr->iptype == WANDDER_IPADDRESS_VERSION_6) {
        addrlen = 16;
    }

    // iP-Type
    wandder_encode_next_ber(enc_ber, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, (uint8_t*)&(iptype),
            sizeof(iptype));

    wandder_encode_next_ber(enc_ber, WANDDER_TAG_SEQUENCE,
            WANDDER_CLASS_CONTEXT_CONSTRUCT, 2, NULL,
            0);

    if (addr->valtype == WANDDER_IPADDRESS_REP_BINARY) {
        wandder_encode_next_ber(enc_ber, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, addr->ipvalue,
            addrlen);
    } else {
        wandder_encode_next_ber(enc_ber, WANDDER_TAG_IA5,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, addr->ipvalue,
            strlen((char *)addr->ipvalue));
    }

    wandder_encode_endseq_ber(enc_ber, 1);

    // iP-assignment
    wandder_encode_next_ber(enc_ber, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 3, (uint8_t*)&(assign),
            sizeof(assign));

    // iPv6PrefixLength
    if (addr->v6prefixlen > 0) {
        wandder_encode_next_ber(enc_ber, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, (uint8_t *)&(prefbits),
            sizeof(prefbits));
    }

    // iPv4SubnetMask
    if (addr->v4subnetmask > 0) {
        wandder_encode_next_ber(enc_ber, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 5, 
                (uint8_t *)&(addr->v4subnetmask),
                sizeof(addr->v4subnetmask));
    }

    free(addr->ipvalue);
}

//ensures that the buffer exceeds child->body.buf + currlen in allocated memeroy
//adjusts all internal pointers accordingly if realloc
//returns the difference between new, and old buffers
static ptrdiff_t check_body_size(wandder_etsili_child_t * child, size_t currlen){
    
    uint8_t* new;
    ptrdiff_t offset = 0;

    if (currlen + (child->body.data - child->buf) > child->alloc_len){
        child->alloc_len = child->len + currlen + child->owner->increment_len;
        child->body.alloc_len = child->alloc_len - child->header.len;
        new = realloc(child->buf, child->alloc_len);
        if (new == NULL){
            //TODO handle realloc fail
            fprintf(stderr, "unable to alloc mem\n");
            assert(0);
        }
        
        //update all refrences
        if (new != child->body.buf){ //only need to update if alloc moved
            ptrdiff_t offset = (new - child->buf);
            child->buf          += offset;
            child->header.buf   += offset;
            child->header.cin   += offset;
            child->header.seqno += offset;
            child->header.sec   += offset;
            child->header.usec  += offset;
            child->header.end   += offset;

            child->body.buf     += offset;
            child->body.meta    += offset; 
            child->body.data    += offset;
            return offset;
        }
    }
    return offset;
}

inline static void preencoded_here(uint8_t** ptr, ptrdiff_t * rem, int index, 
        wandder_etsili_child_t * child) {

    size_t ret = child->owner->preencoded[index]->len;
    *ptr += check_body_size(child, (*ptr - child->body.buf) + ret);
    memcpy(*ptr, 
            child->owner->preencoded[index]->buf, ret);
    *ptr += ret;
    *rem = child->alloc_len - (*ptr - child->buf);
}

inline static void encode_here_ber_update(
        uint8_t idnum, uint8_t class, uint8_t encodeas, 
        void * valptr, size_t vallen, 
        uint8_t** ptr, ptrdiff_t* rem,
        wandder_etsili_child_t * child){

    *ptr += check_body_size(child, (*ptr - child->body.buf) + 512);
    size_t ret = encode_here_ber(
                idnum,
                class,
                encodeas,
                valptr, 
                vallen,
                *ptr,
                *rem);
    *ptr += ret;
    *rem = child->alloc_len - (*ptr - child->buf);
}

static inline void encode_ipaddress_inplace(
        uint8_t** ptr, ptrdiff_t* rem, wandder_etsili_child_t * child,
        wandder_etsili_ipaddress_t *addr) {

    uint32_t addrlen = 4;
    uint32_t iptype = addr->iptype;
    uint32_t assign = addr->assignment;
    uint32_t prefbits = addr->v6prefixlen;

    if (addr->iptype == WANDDER_IPADDRESS_VERSION_6) {
        addrlen = 16;
    }

    // iP-Type
    encode_here_ber_update(
            1, WANDDER_CLASS_CONTEXT_PRIMITIVE, WANDDER_TAG_ENUM,
            (uint8_t*)&(iptype), sizeof(iptype),
            ptr, rem, child);

    encode_here_ber_update(
            2, WANDDER_CLASS_CONTEXT_CONSTRUCT, WANDDER_TAG_SEQUENCE,
            NULL, 0,
            ptr, rem, child);

    if (addr->valtype == WANDDER_IPADDRESS_REP_BINARY) {
        encode_here_ber_update(
                1, WANDDER_CLASS_CONTEXT_PRIMITIVE, WANDDER_TAG_OCTETSTRING,
                addr->ipvalue, addrlen,
                ptr, rem, child);
    } else {
        encode_here_ber_update(
                2, WANDDER_CLASS_CONTEXT_PRIMITIVE, WANDDER_TAG_IA5,
                addr->ipvalue, strlen((char *)addr->ipvalue),
                ptr, rem, child);
    }

    ENDCONSTRUCTEDBLOCK(*ptr, 1)
    *rem -= 2;

    // iP-assignment
    encode_here_ber_update(
            3, WANDDER_CLASS_CONTEXT_PRIMITIVE, WANDDER_TAG_ENUM,
            (uint8_t*)&(assign), sizeof(assign),
            ptr, rem, child);

    // iPv6PrefixLength
    if (addr->v6prefixlen > 0) {
        encode_here_ber_update(
                4, WANDDER_CLASS_CONTEXT_PRIMITIVE, WANDDER_TAG_INTEGER,
                (uint8_t*)&(prefbits), sizeof(prefbits),
                ptr, rem, child);
    }

    // iPv4SubnetMask
    if (addr->v4subnetmask > 0) {
        encode_here_ber_update(
                5, WANDDER_CLASS_CONTEXT_PRIMITIVE, WANDDER_TAG_OCTETSTRING,
                (uint8_t*)&(addr->v4subnetmask), sizeof(addr->v4subnetmask),
                ptr, rem, child);
    }
    free(addr->ipvalue);
}

static void free_generic_body(wandder_generic_body_t * body) {

    wandder_etsili_child_t * head = NULL;
    wandder_etsili_child_t * next = NULL;

    if (body->buf){
        free(body->buf);
    }

    if (body->flist) {
        //obtain lock and remove list from flist to prevent lock contention
        // (could make the mutex recursive instead?)
        if (pthread_mutex_lock(&(body->flist->mutex)) == 0){
            head = body->flist->first;
            body->flist->first = NULL;
            body->flist->marked_for_delete = 1;
            pthread_mutex_unlock(&(body->flist->mutex));
        }
        while (head){
            next = head->nextfree;
            wandder_free_child(head);
            head = next;
        }
        free(body->flist);
    }
} 
static void clear_preencoded_fields_ber( wandder_buf_t **pendarray ) {

    wandder_preencode_index_t i;

    for (i = 0; i < WANDDER_PREENCODE_LAST -1; i++) {
        if (pendarray[i]) {
            free(pendarray[i]->buf);
            free(pendarray[i]);
        }
    }
}

void wandder_free_top(wandder_etsili_top_t *top){
    
    if(top){
        if (top->preencoded){
            clear_preencoded_fields_ber(top->preencoded);
            free(top->preencoded);
        }
        if (top->header.buf)
            free(top->header.buf);

        free_generic_body(&top->ipcc);
        free_generic_body(&top->ipmmcc);
        free_generic_body(&top->ipiri);
        free_generic_body(&top->ipmmiri);
        free_generic_body(&top->umtscc);
        free_generic_body(&top->umtsiri);

        free(top);
    }
}

static wandder_buf_t ** wandder_etsili_preencode_static_fields_ber(
        wandder_etsili_intercept_details_t *details) {

    int tvclass = 1;
    uint32_t dirin = 0, dirout = 1, dirunk = 2;

    wandder_buf_t **pendarray = calloc(sizeof(wandder_buf_t *),
            WANDDER_PREENCODE_LAST);

    pendarray[WANDDER_PREENCODE_USEQUENCE] = wandder_encode_new_ber(
            WANDDER_CLASS_UNIVERSAL_CONSTRUCT, 
            WANDDER_TAG_SEQUENCE,
            WANDDER_TAG_SEQUENCE,
            NULL, 
            0);

    pendarray[WANDDER_PREENCODE_CSEQUENCE_0] =  wandder_encode_new_ber(
            WANDDER_CLASS_CONTEXT_CONSTRUCT, 
            0,
            WANDDER_TAG_SEQUENCE,
            NULL, 
            0);

    pendarray[WANDDER_PREENCODE_CSEQUENCE_1] =  wandder_encode_new_ber(
            WANDDER_CLASS_CONTEXT_CONSTRUCT, 
            1,
            WANDDER_TAG_SEQUENCE,
            NULL, 
            0);

    pendarray[WANDDER_PREENCODE_CSEQUENCE_2] =  wandder_encode_new_ber(
            WANDDER_CLASS_CONTEXT_CONSTRUCT, 
            2,
            WANDDER_TAG_SEQUENCE,
            NULL, 
            0);

    pendarray[WANDDER_PREENCODE_CSEQUENCE_3] =  wandder_encode_new_ber(
            WANDDER_CLASS_CONTEXT_CONSTRUCT, 
            3,
            WANDDER_TAG_SEQUENCE,
            NULL, 
            0);

    pendarray[WANDDER_PREENCODE_CSEQUENCE_4] =  wandder_encode_new_ber(
            WANDDER_CLASS_CONTEXT_CONSTRUCT, 
            4,
            WANDDER_TAG_SEQUENCE,
            NULL, 
            0);

    pendarray[WANDDER_PREENCODE_CSEQUENCE_5] =  wandder_encode_new_ber(
            WANDDER_CLASS_CONTEXT_CONSTRUCT, 
            5,
            WANDDER_TAG_SEQUENCE,
            NULL, 
            0);

    pendarray[WANDDER_PREENCODE_CSEQUENCE_7] =  wandder_encode_new_ber(
            WANDDER_CLASS_CONTEXT_CONSTRUCT, 
            7,
            WANDDER_TAG_SEQUENCE,
            NULL, 
            0);

    pendarray[WANDDER_PREENCODE_CSEQUENCE_8] =  wandder_encode_new_ber(
            WANDDER_CLASS_CONTEXT_CONSTRUCT, 
            8,
            WANDDER_TAG_SEQUENCE,
            NULL, 
            0);

    pendarray[WANDDER_PREENCODE_CSEQUENCE_9] =  wandder_encode_new_ber(
            WANDDER_CLASS_CONTEXT_CONSTRUCT, 
            9,
            WANDDER_TAG_SEQUENCE,
            NULL, 
            0);

    pendarray[WANDDER_PREENCODE_CSEQUENCE_11] =  wandder_encode_new_ber(
            WANDDER_CLASS_CONTEXT_CONSTRUCT, 
            11,
            WANDDER_TAG_SEQUENCE,
            NULL, 
            0);

    pendarray[WANDDER_PREENCODE_CSEQUENCE_12] =  wandder_encode_new_ber(
            WANDDER_CLASS_CONTEXT_CONSTRUCT, 
            12,
            WANDDER_TAG_SEQUENCE,
            NULL, 
            0);

    pendarray[WANDDER_PREENCODE_CSEQUENCE_13] =  wandder_encode_new_ber(
            WANDDER_CLASS_CONTEXT_CONSTRUCT, 
            13,
            WANDDER_TAG_SEQUENCE,
            NULL, 
            0);

    pendarray[WANDDER_PREENCODE_CSEQUENCE_26] =  wandder_encode_new_ber(
            WANDDER_CLASS_CONTEXT_CONSTRUCT, 
            26,
            WANDDER_TAG_SEQUENCE,
            NULL, 
            0);

    //TODO i dont think this is 100% correct but i cant see anything wrong
    pendarray[WANDDER_PREENCODE_PSDOMAINID] =  wandder_encode_new_ber( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_OID,
            (uint8_t *)WANDDER_ETSILI_PSDOMAINID, 
            sizeof WANDDER_ETSILI_PSDOMAINID);

    pendarray[WANDDER_PREENCODE_LIID] =  wandder_encode_new_ber( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            1,
            WANDDER_TAG_OCTETSTRING,
            (uint8_t *)details->liid, 
            strlen(details->liid));

    pendarray[WANDDER_PREENCODE_AUTHCC] =  wandder_encode_new_ber( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            2,
            WANDDER_TAG_OCTETSTRING,
            (uint8_t *)details->authcc, 
            strlen(details->authcc));

    pendarray[WANDDER_PREENCODE_OPERATORID] =  wandder_encode_new_ber( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_OCTETSTRING,
            (uint8_t *)details->operatorid, 
            strlen(details->operatorid));

    pendarray[WANDDER_PREENCODE_NETWORKELEMID] =  wandder_encode_new_ber( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            1,
            WANDDER_TAG_OCTETSTRING,
            (uint8_t *)details->networkelemid, 
            strlen(details->networkelemid));

    pendarray[WANDDER_PREENCODE_DELIVCC] =  wandder_encode_new_ber( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            2,
            WANDDER_TAG_OCTETSTRING,
            (uint8_t *)details->delivcc, 
            strlen(details->delivcc));

    //either build the field or set it NULL
    pendarray[WANDDER_PREENCODE_INTPOINTID] = (details->intpointid) ? 
            wandder_encode_new_ber( 
                    WANDDER_CLASS_CONTEXT_PRIMITIVE,
                    6,
                    WANDDER_TAG_OCTETSTRING,
                    (uint8_t *)details->intpointid,
                    strlen(details->intpointid)) :
            NULL;

    pendarray[WANDDER_PREENCODE_TVCLASS] =  wandder_encode_new_ber( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            8,
            WANDDER_TAG_ENUM,
            (uint8_t *)(&tvclass), 
            sizeof tvclass);

    pendarray[WANDDER_PREENCODE_IPMMIRIOID] =  wandder_encode_new_ber( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_RELATIVEOID,
            etsi_ipmmirioid, 
            sizeof etsi_ipmmirioid);

    pendarray[WANDDER_PREENCODE_IPCCOID] =  wandder_encode_new_ber( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_RELATIVEOID,
            etsi_ipccoid, 
            sizeof etsi_ipccoid);

    pendarray[WANDDER_PREENCODE_IPIRIOID] =  wandder_encode_new_ber( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_RELATIVEOID,
            etsi_ipirioid, 
            sizeof etsi_ipirioid);

    pendarray[WANDDER_PREENCODE_UMTSIRIOID] =  wandder_encode_new_ber( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_OID,
            etsi_umtsirioid, 
            sizeof etsi_umtsirioid);

    pendarray[WANDDER_PREENCODE_IPMMCCOID] =  wandder_encode_new_ber( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_RELATIVEOID,
            etsi_ipmmccoid, 
            sizeof etsi_ipmmccoid);

    pendarray[WANDDER_PREENCODE_DIRFROM] =  wandder_encode_new_ber( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_ENUM,
            (uint8_t *)(&dirin), 
            sizeof dirin);

    pendarray[WANDDER_PREENCODE_DIRTO] =  wandder_encode_new_ber( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_ENUM,
            (uint8_t *)(&dirout), 
            sizeof dirout);

    pendarray[WANDDER_PREENCODE_DIRUNKNOWN] =  wandder_encode_new_ber( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_ENUM,
            (uint8_t *)(&dirunk), 
            sizeof dirunk);
    pendarray[WANDDER_PREENCODE_LIID_LEN] = (void *)((size_t)strlen(details->liid));

    return pendarray;

}

static int sort_etsili_generic(
        wandder_etsili_generic_t *a, 
        wandder_etsili_generic_t *b) {

    if (a->itemnum < b->itemnum) {
        return -1;
    }
    if (a->itemnum > b->itemnum) {
        return 1;
    }
    return 0;
}

static uint8_t* wandder_encode_body_data_ber(
        wandder_etsili_child_t* child,
        uint8_t class, 
        uint8_t idnum, 
        uint8_t encodeas, 
        uint8_t * valptr,
        size_t vallen){

    ptrdiff_t currlen = calculate_length(idnum, class, encodeas, vallen); 
    
    //if new length cannot fit in old space make more
    // if currlen+(currptr-baseptr) > alloclen
    check_body_size(child, currlen);

    ptrdiff_t rem = child->alloc_len - (child->body.data - child->buf);

    size_t ret = encode_here_ber(idnum, class, encodeas, valptr, vallen, 
            child->body.data, rem);

    return ret + child->body.data;
}

static void update_etsili_pshdr_pc(wandder_pshdr_t * header, int64_t cin,
        int64_t seqno, struct timeval* tv){

    ber_rebuild_integer(
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            1, 
            &(cin), 
            sizeof cin,
            header->cin);

    ber_rebuild_integer(
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            4, 
            &(seqno), 
            sizeof seqno,
            header->seqno);

    ber_rebuild_integer(
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0, 
            &(tv->tv_sec), 
            sizeof tv->tv_sec,
            header->sec);

    ber_rebuild_integer(
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            1, 
            &(tv->tv_usec), 
            sizeof tv->tv_usec,
            header->usec);
}

static void init_etsili_pshdr_pc(wandder_encoder_ber_t* enc_ber, 
        wandder_etsili_top_t* top) {

    int64_t cin = 0;
    int64_t seqno = 0;
    struct timeval tv = {0,0};

    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_USEQUENCE]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_1]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_PSDOMAINID]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_LIID]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_AUTHCC]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_3]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_0]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_OPERATORID]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_NETWORKELEMID]);
    wandder_encode_endseq_ber(enc_ber, 1);

    ptrdiff_t cin_diff = enc_ber->ptr - enc_ber->buf;
    wandder_encode_next_ber(enc_ber, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &(cin),
            sizeof cin);

    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_DELIVCC]);
    wandder_encode_endseq_ber(enc_ber, 1);

    ptrdiff_t seqno_diff = enc_ber->ptr - enc_ber->buf;
    wandder_encode_next_ber(enc_ber, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, &(seqno),
            sizeof seqno);

    if (top->preencoded[WANDDER_PREENCODE_INTPOINTID]) {
        wandder_append_preencoded_ber(enc_ber, 
                top->preencoded[WANDDER_PREENCODE_INTPOINTID]);
    }
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_7]);

    ptrdiff_t sec_diff = enc_ber->ptr - enc_ber->buf;
    wandder_encode_next_ber(enc_ber, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &(tv.tv_sec),
            sizeof tv.tv_sec);

    ptrdiff_t usec_diff = enc_ber->ptr - enc_ber->buf;
    wandder_encode_next_ber(enc_ber, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &(tv.tv_usec),
            sizeof tv.tv_usec);

    wandder_encode_endseq_ber(enc_ber, 1);

    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_TVCLASS]);
    wandder_encode_endseq_ber(enc_ber, 1);
    ptrdiff_t end_diff = enc_ber->ptr - enc_ber->buf;


    wandder_encoded_result_ber_t* res_ber = wandder_encode_finish_ber(enc_ber);

    top->header.buf             = res_ber->buf;
    top->header.len             = res_ber->len;
    top->header.cin             = res_ber->buf + cin_diff;
    top->header.seqno           = res_ber->buf + seqno_diff;
    top->header.sec             = res_ber->buf + sec_diff;
    top->header.usec            = res_ber->buf + usec_diff;
    top->header.end             = res_ber->buf + end_diff;

    free(res_ber);
}

static void update_etsili_ipcc(
        void* ipcontents, size_t iplen, uint8_t dir, 
        wandder_etsili_child_t * child) {
    if (dir == 0) {
        memcpy(child->body.meta, 
                child->owner->preencoded[WANDDER_PREENCODE_DIRFROM]->buf, 
                child->owner->preencoded[WANDDER_PREENCODE_DIRFROM]->len);
    } else if (dir == 1) {
        memcpy(child->body.meta, 
                child->owner->preencoded[WANDDER_PREENCODE_DIRTO]->buf, 
                child->owner->preencoded[WANDDER_PREENCODE_DIRTO]->len);
    } else if (dir == 2) {
        memcpy(child->body.meta, 
                child->owner->preencoded[WANDDER_PREENCODE_DIRUNKNOWN]->buf, 
                child->owner->preencoded[WANDDER_PREENCODE_DIRUNKNOWN]->len);
    } else {
        ber_rebuild_integer(
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0, 
            &(dir), 
            sizeof dir,
            child->body.meta);
    }

    uint8_t* ptr = wandder_encode_body_data_ber(
            child,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_IPPACKET,
            ipcontents, 
            iplen);

    ptr += check_body_size(child, (ptr - child->body.buf) + (7*2));
    ENDCONSTRUCTEDBLOCK(ptr,7)
    child->body.len = ptr - child->body.buf;
    child->len = ptr - child->buf;

}

static void update_etsili_ipmmcc(
        void* ipcontents, size_t iplen, uint8_t dir, 
        wandder_etsili_child_t * child) {

    uint32_t frametype = 0; //TODO these are hard coded to 0? 
    uint32_t mmccproto = 0; //at least they are in etsili_core.c in OpenLI

    if (dir == 0) {
        memcpy(child->body.meta, 
                child->owner->preencoded[WANDDER_PREENCODE_DIRFROM]->buf, 
                child->owner->preencoded[WANDDER_PREENCODE_DIRFROM]->len);
    } else if (dir == 1) {
        memcpy(child->body.meta, 
                child->owner->preencoded[WANDDER_PREENCODE_DIRTO]->buf, 
                child->owner->preencoded[WANDDER_PREENCODE_DIRTO]->len);
    } else if (dir == 2) {
        memcpy(child->body.meta, 
                child->owner->preencoded[WANDDER_PREENCODE_DIRUNKNOWN]->buf, 
                child->owner->preencoded[WANDDER_PREENCODE_DIRUNKNOWN]->len);
    } else {
        ber_rebuild_integer(
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0, 
            &(dir), 
            sizeof dir,
            child->body.meta);
    }

    uint8_t* ptr = wandder_encode_body_data_ber(
            child,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            1,
            WANDDER_TAG_IPPACKET,
            ipcontents, 
            iplen);

    //ensure there is enough space for the last section
    ptr += check_body_size(child, (ptr - child->body.buf) +
            (6*2) + (child->owner->preencoded[WANDDER_PREENCODE_DIRUNKNOWN]->len *2));

    ptr += ber_rebuild_integer(
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            2, 
            &(frametype), 
            sizeof frametype,
            ptr);

    ptr += ber_rebuild_integer(
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            4, 
            &(mmccproto), 
            sizeof mmccproto,
            ptr);
    
    ENDCONSTRUCTEDBLOCK(ptr,6) //endseq
    child->body.len = ptr - child->body.buf;
    child->len = ptr - child->buf;
}

static void update_etsili_ipmmiri(
        void* ipcontents, size_t iplen, wandder_etsili_iri_type_t iritype, 
        wandder_etsili_child_t * child) {

    ber_rebuild_integer(
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0, 
            &(iritype), 
            sizeof iritype,
            child->body.meta);

    uint8_t* ptr = wandder_encode_body_data_ber(
            child,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            2,
            WANDDER_TAG_IPPACKET,
            ipcontents, 
            iplen);

    //ensure there is enough space for the last section
    ptr += check_body_size(child, (ptr - child->body.buf) + (8*2));
    ENDCONSTRUCTEDBLOCK(ptr,8)
    child->body.len = ptr - child->body.buf;
    child->len = ptr - child->buf;
}

static void update_etsili_ipiri(
        wandder_etsili_generic_t *params, wandder_etsili_iri_type_t iritype, 
        wandder_etsili_child_t * child) {

    wandder_etsili_generic_t *p, *tmp;
    wandder_ipiri_id_t* iriid;
    size_t ret;
    uint8_t * ptr = child->body.data;
    ptrdiff_t data_ptr_diff = ptr - child->buf;
    ptrdiff_t rem = child->alloc_len - (ptr - child->buf);
    
    ber_rebuild_integer(
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0, 
            &(iritype), 
            sizeof iritype,
            child->body.meta);

    //do params here from
    HASH_SRT(hh, params, sort_etsili_generic);
    HASH_ITER(hh, params, p, tmp) {
        ptr += check_body_size(child, (ptr - child->body.buf) + 512);
        rem = child->alloc_len - (ptr - child->buf);
        //need a better way then just making it bigger before hand (maybe?)
        switch(p->itemnum) {
            case WANDDER_IPIRI_CONTENTS_ACCESS_EVENT_TYPE:
            case WANDDER_IPIRI_CONTENTS_INTERNET_ACCESS_TYPE:
            case WANDDER_IPIRI_CONTENTS_IPVERSION:
            case WANDDER_IPIRI_CONTENTS_ENDREASON:
            case WANDDER_IPIRI_CONTENTS_AUTHENTICATION_TYPE:
                ret = encode_here_ber(
                        p->itemnum,
                        WANDDER_CLASS_CONTEXT_PRIMITIVE,
                        WANDDER_TAG_ENUM,
                        p->itemptr,
                        p->itemlen, 
                        ptr, rem);
                ptr += ret;
                rem -= ret;
                break;

            case WANDDER_IPIRI_CONTENTS_TARGET_USERNAME:
            case WANDDER_IPIRI_CONTENTS_RAW_AAA_DATA:
                ret = encode_here_ber(
                        p->itemnum,
                        WANDDER_CLASS_CONTEXT_PRIMITIVE,
                        WANDDER_TAG_OCTETSTRING,
                        p->itemptr,
                        p->itemlen, 
                        ptr, rem);
                ptr += ret;
                rem -= ret;
                break;

            case WANDDER_IPIRI_CONTENTS_TARGET_IPADDRESS:
            case WANDDER_IPIRI_CONTENTS_POP_IPADDRESS:
            case WANDDER_IPIRI_CONTENTS_ADDITIONAL_IPADDRESS:
                encode_here_ber_update(
                        p->itemnum, WANDDER_CLASS_CONTEXT_CONSTRUCT, WANDDER_TAG_SEQUENCE,
                        NULL, 0,
                        &ptr, &rem, child);
                encode_ipaddress_inplace(
                        &ptr, 
                        &rem, 
                        child, 
                        (wandder_etsili_ipaddress_t *)(p->itemptr));
                ENDCONSTRUCTEDBLOCK(ptr,1)
                break;

            case WANDDER_IPIRI_CONTENTS_POP_IDENTIFIER:
                iriid = (wandder_ipiri_id_t *)p->itemptr;
                ret = encode_here_ber(
                        p->itemnum,
                        WANDDER_CLASS_CONTEXT_CONSTRUCT,
                        WANDDER_TAG_SEQUENCE,
                        NULL,
                        0, 
                        ptr, rem);
                ptr += ret;
                rem -= ret;
                if (iriid->type == WANDDER_IPIRI_ID_PRINTABLE) {
                    ret = encode_here_ber(
                            0,
                            WANDDER_CLASS_CONTEXT_PRIMITIVE,
                            WANDDER_TAG_UTF8STR,
                            (uint8_t *)iriid->content.printable,
                            strlen(iriid->content.printable),
                            ptr, rem);
                    ptr += ret;
                    rem -= ret;
                } else if (iriid->type == WANDDER_IPIRI_ID_MAC) {
                    ret = encode_here_ber(
                            1,
                            WANDDER_CLASS_CONTEXT_PRIMITIVE,
                            WANDDER_TAG_OCTETSTRING,
                            iriid->content.mac,
                            6,
                            ptr, rem);
                    ptr += ret;
                    rem -= ret;
                } else if (iriid->type == WANDDER_IPIRI_ID_IPADDR) {
                    ret = encode_here_ber(
                            2,
                            WANDDER_CLASS_CONTEXT_CONSTRUCT,
                            WANDDER_TAG_SEQUENCE,
                            NULL,
                            0,
                            ptr, rem);
                    ptr += ret;
                    rem -= ret;
                    //encode_ipaddress(enc_ber, iriid->content.ip);
                    ENDCONSTRUCTEDBLOCK(ptr, 1)
                }
                ENDCONSTRUCTEDBLOCK(ptr, 1)
                break;

            case WANDDER_IPIRI_CONTENTS_NATIONAL_IPIRI_PARAMETERS:
                /* TODO NationalIPIRIParameters */
                break;

            case WANDDER_IPIRI_CONTENTS_OTHER_TARGET_IDENTIFIERS:
                /* TODO */
                break;

            case WANDDER_IPIRI_CONTENTS_POP_PORTNUMBER:
            case WANDDER_IPIRI_CONTENTS_OCTETS_RECEIVED:
            case WANDDER_IPIRI_CONTENTS_OCTETS_TRANSMITTED:
                ret = encode_here_ber(
                        p->itemnum,
                        WANDDER_CLASS_CONTEXT_PRIMITIVE,
                        WANDDER_TAG_INTEGER,
                        p->itemptr,
                        p->itemlen,
                        ptr, rem);
                ptr += ret;
                rem -= ret;
                break;

            case WANDDER_IPIRI_CONTENTS_STARTTIME:
            case WANDDER_IPIRI_CONTENTS_ENDTIME:
            case WANDDER_IPIRI_CONTENTS_EXPECTED_ENDTIME:
                if (p->itemlen != sizeof(struct timeval)) {
                    break;
                }
                ret = encode_here_ber(
                            p->itemnum,
                            WANDDER_CLASS_CONTEXT_PRIMITIVE,
                            WANDDER_TAG_GENERALTIME,
                            p->itemptr,
                            p->itemlen,
                            ptr, rem);
                ptr += ret;
                rem -= ret;
                break;

            case WANDDER_IPIRI_CONTENTS_TARGET_NETWORKID:
            case WANDDER_IPIRI_CONTENTS_TARGET_CPEID:
            case WANDDER_IPIRI_CONTENTS_TARGET_LOCATION:
            case WANDDER_IPIRI_CONTENTS_CALLBACK_NUMBER:
            case WANDDER_IPIRI_CONTENTS_POP_PHONENUMBER:
                /* TODO enforce max string lens */
                ret = encode_here_ber(
                            p->itemnum,
                            WANDDER_CLASS_CONTEXT_PRIMITIVE,
                            WANDDER_TAG_UTF8STR,
                            p->itemptr,
                            p->itemlen,
                            ptr, rem);
                ptr += ret;
                rem -= ret;
                break;
        }
    }

    //ensure there is enough space for the last section
    child->body.data = data_ptr_diff + child->buf;
    ptr += check_body_size(child, (ptr - child->body.buf) + (8*2));
    ENDCONSTRUCTEDBLOCK(ptr,7) //endseq
    child->body.len = ptr - child->body.buf;
    child->len = ptr - child->buf;

}

static void update_etsili_umtscc(
        void* ipcontents, size_t iplen, uint8_t dir, 
        wandder_etsili_child_t * child) {
    if (dir == 0) {
        memcpy(child->body.meta, 
                child->owner->preencoded[WANDDER_PREENCODE_DIRFROM]->buf, 
                child->owner->preencoded[WANDDER_PREENCODE_DIRFROM]->len);
    } else if (dir == 1) {
        memcpy(child->body.meta, 
                child->owner->preencoded[WANDDER_PREENCODE_DIRTO]->buf, 
                child->owner->preencoded[WANDDER_PREENCODE_DIRTO]->len);
    } else if (dir == 2) {
        memcpy(child->body.meta, 
                child->owner->preencoded[WANDDER_PREENCODE_DIRUNKNOWN]->buf, 
                child->owner->preencoded[WANDDER_PREENCODE_DIRUNKNOWN]->len);
    } else {
        ber_rebuild_integer(
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0, 
            &(dir), 
            sizeof dir,
            child->body.meta);
    }

    uint8_t* ptr = wandder_encode_body_data_ber(
            child,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            4,
            WANDDER_TAG_IPPACKET,
            ipcontents, 
            iplen);

    ptr += check_body_size(child, (ptr - child->body.buf) + (5*2));
    ENDCONSTRUCTEDBLOCK(ptr,5)
    child->body.len = ptr - child->body.buf;
    child->len = ptr - child->buf;

}

static void update_etsili_umtsiri(
        wandder_etsili_generic_t *params, wandder_etsili_iri_type_t iritype, 
        wandder_etsili_child_t * child) {

    wandder_etsili_generic_t *p, *savedtime;
    size_t ret;
    uint8_t lookup;
    uint32_t iriversion = 8;
    uint32_t gprstarget = 3;
    uint8_t * ptr = child->body.meta; //start from meta,
    ptrdiff_t data_ptr_diff = ptr - child->buf;
    ptrdiff_t rem;
    
    ptr += check_body_size(child, (ptr - child->body.buf) + 512);
    ret = ber_rebuild_integer(
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0, 
            &(iritype), 
            sizeof iritype,
            child->body.meta);
    ptr += ret;
    rem = child->alloc_len - (ptr - child->buf);
    
/* timeStamp -- as generalized time */
    lookup = WANDDER_UMTSIRI_CONTENTS_EVENT_TIME;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        encode_here_ber_update(
                1, WANDDER_CLASS_CONTEXT_PRIMITIVE, WANDDER_TAG_GENERALTIME,
                p->itemptr, p->itemlen,
                &ptr, &rem, child);
        savedtime = p;
    } else {
        savedtime = NULL;
        fprintf(stderr,
                "wandder: warning, no timestamp available for constructing UMTS IRI\n");
        fprintf(stderr, "wandder: UMTS IRI record may be invalid...\n");
    }
    preencoded_here(&ptr, &rem, WANDDER_PREENCODE_CSEQUENCE_2, child);
    preencoded_here(&ptr, &rem, WANDDER_PREENCODE_CSEQUENCE_4, child);
    preencoded_here(&ptr, &rem, WANDDER_PREENCODE_CSEQUENCE_0, child);

    /* IRI-Parameters start here */

    /* Object identifier (0) */
    preencoded_here(&ptr, &rem, WANDDER_PREENCODE_UMTSIRIOID, child);

    /* LIID (1) -- fortunately the identifier matches the one
     * used in the PSHeader, so we can use our preencoded
     * version */

    preencoded_here(&ptr, &rem, WANDDER_PREENCODE_LIID, child);    

    /* timeStamp again (3) -- different format, use UTCTime */
    preencoded_here(&ptr, &rem, WANDDER_PREENCODE_CSEQUENCE_3, child);

    if (savedtime) {
        encode_here_ber_update(
                1, WANDDER_CLASS_CONTEXT_PRIMITIVE, WANDDER_TAG_UTCTIME,
                savedtime->itemptr, savedtime->itemlen,
                &ptr, &rem, child);
    }
    ENDCONSTRUCTEDBLOCK(ptr, 1)

    /* initiator (4) */
    lookup = WANDDER_UMTSIRI_CONTENTS_INITIATOR;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (!p) {
        fprintf(stderr, "wandder: warning, no initiator available for constructing UMTS IRI\n");
        fprintf(stderr, "wandder: UMTS IRI record may be invalid...\n");
    } else {
        encode_here_ber_update(
                4, WANDDER_CLASS_CONTEXT_PRIMITIVE, WANDDER_TAG_ENUM,
                p->itemptr, p->itemlen,
                &ptr, &rem, child);
    }

    /* location, if available (8) -- nested */
    preencoded_here(&ptr, &rem, WANDDER_PREENCODE_CSEQUENCE_8, child);

    lookup = WANDDER_UMTSIRI_CONTENTS_CGI;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        encode_here_ber_update(
                2, WANDDER_CLASS_CONTEXT_PRIMITIVE, WANDDER_TAG_OCTETSTRING,
                p->itemptr, p->itemlen,
                &ptr, &rem, child);
    }

    lookup = WANDDER_UMTSIRI_CONTENTS_SAI;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        encode_here_ber_update(
                7, WANDDER_CLASS_CONTEXT_PRIMITIVE, WANDDER_TAG_OCTETSTRING,
                p->itemptr, p->itemlen,
                &ptr, &rem, child);
    }

    lookup = WANDDER_UMTSIRI_CONTENTS_TAI;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        encode_here_ber_update(
                9, WANDDER_CLASS_CONTEXT_PRIMITIVE, WANDDER_TAG_OCTETSTRING,
                p->itemptr, p->itemlen,
                &ptr, &rem, child);
    }

    lookup = WANDDER_UMTSIRI_CONTENTS_ECGI;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        rem -= ret;
        encode_here_ber_update(
                10, WANDDER_CLASS_CONTEXT_PRIMITIVE, WANDDER_TAG_OCTETSTRING,
                p->itemptr, p->itemlen,
                &ptr, &rem, child);
    }

    preencoded_here(&ptr, &rem, WANDDER_PREENCODE_CSEQUENCE_13, child);
    preencoded_here(&ptr, &rem, WANDDER_PREENCODE_CSEQUENCE_0, child);

    lookup = WANDDER_UMTSIRI_CONTENTS_LOCATION_TIME;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        encode_here_ber_update(
                0, WANDDER_CLASS_CONTEXT_PRIMITIVE, WANDDER_TAG_UTCTIME,
                p->itemptr, p->itemlen,
                &ptr, &rem, child);
    }
    ENDCONSTRUCTEDBLOCK(ptr,3)

    /* party information (9) -- nested */
    preencoded_here(&ptr, &rem, WANDDER_PREENCODE_CSEQUENCE_9, child);

    encode_here_ber_update(
                0, WANDDER_CLASS_CONTEXT_PRIMITIVE, WANDDER_TAG_ENUM,
                &gprstarget, sizeof(gprstarget),
                &ptr, &rem, child);

    preencoded_here(&ptr, &rem, WANDDER_PREENCODE_CSEQUENCE_1, child);

    lookup = WANDDER_UMTSIRI_CONTENTS_IMEI;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        encode_here_ber_update(
                1, WANDDER_CLASS_CONTEXT_PRIMITIVE, WANDDER_TAG_OCTETSTRING,
                p->itemptr, p->itemlen,
                &ptr, &rem, child);
    } else {
        fprintf(stderr, "wandder: warning, no IMEI available for constructing UMTS IRI\n");
        fprintf(stderr, "wandder: UMTS IRI record may be invalid...\n");
    }

    lookup = WANDDER_UMTSIRI_CONTENTS_IMSI;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        encode_here_ber_update(
                3, WANDDER_CLASS_CONTEXT_PRIMITIVE, WANDDER_TAG_OCTETSTRING,
                p->itemptr, p->itemlen,
                &ptr, &rem, child);
    } else {
        fprintf(stderr, "wandder: warning, no IMSI available for constructing UMTS IRI\n");
        fprintf(stderr, "wandder: UMTS IRI record may be invalid...\n");
    }

    lookup = WANDDER_UMTSIRI_CONTENTS_MSISDN;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        encode_here_ber_update(
                6, WANDDER_CLASS_CONTEXT_PRIMITIVE, WANDDER_TAG_OCTETSTRING,
                p->itemptr, p->itemlen,
                &ptr, &rem, child);
    } else {
        fprintf(stderr, "wandder: warning, no MSISDN available for constructing UMTS IRI\n");
        fprintf(stderr, "wandder: UMTS IRI record may be invalid...\n");
    }

    ENDCONSTRUCTEDBLOCK(ptr,1)

    /* servicesDataInformation (pdpAddress, APN etc) */
    preencoded_here(&ptr, &rem, WANDDER_PREENCODE_CSEQUENCE_4, child);       // services-data-information
    preencoded_here(&ptr, &rem, WANDDER_PREENCODE_CSEQUENCE_1, child);       // gprs-parameters

    lookup = WANDDER_UMTSIRI_CONTENTS_PDP_ADDRESS;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        preencoded_here(&ptr, &rem, WANDDER_PREENCODE_CSEQUENCE_1, child);       // pdp-address
        preencoded_here(&ptr, &rem, WANDDER_PREENCODE_CSEQUENCE_1, child);       // datanodeaddress
        encode_ipaddress_inplace(&ptr, &rem, child, (wandder_etsili_ipaddress_t *)(p->itemptr));
        ENDCONSTRUCTEDBLOCK(ptr,2)
    } else {
        fprintf(stderr, "wandder: warning, no PDP Address available for constructing UMTS IRI\n");
        fprintf(stderr, "wandder: UMTS IRI record may be invalid...\n");
    }

    /* TODO figure out if we need to include the "length" field in our
     * encoding.
     */
    lookup = WANDDER_UMTSIRI_CONTENTS_APNAME;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        encode_here_ber_update(
                2, WANDDER_CLASS_CONTEXT_PRIMITIVE, WANDDER_TAG_OCTETSTRING,
                p->itemptr, p->itemlen,
                &ptr, &rem, child);
    }

    lookup = WANDDER_UMTSIRI_CONTENTS_PDPTYPE;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        encode_here_ber_update(
                3, WANDDER_CLASS_CONTEXT_PRIMITIVE, WANDDER_TAG_OCTETSTRING,
                p->itemptr, p->itemlen,
                &ptr, &rem, child);
    }

    ENDCONSTRUCTEDBLOCK(ptr,3)

    /* gprs correlation number (18) */
    lookup = WANDDER_UMTSIRI_CONTENTS_GPRS_CORRELATION;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (!p) {
        fprintf(stderr, "wandder: warning, no GPRS correlation number available for constructing UMTS IRI\n");
        fprintf(stderr, "wandder: UMTS IRI record may be invalid...\n");
    } else {
        char space[24];
        snprintf(space, 24, "%lu", *((long *)(p->itemptr)));

        encode_here_ber_update(
                18, WANDDER_CLASS_CONTEXT_PRIMITIVE, WANDDER_TAG_OCTETSTRING,
                space, strlen(space),
                &ptr, &rem, child);
    }

    /* gprs event (20) */
    lookup = WANDDER_UMTSIRI_CONTENTS_EVENT_TYPE;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (!p) {
        fprintf(stderr, "wandder: warning, no GPRS event type available for constructing UMTS IRI\n");
        fprintf(stderr, "wandder: UMTS IRI record may be invalid...\n");
    } else {
        encode_here_ber_update(
                20, WANDDER_CLASS_CONTEXT_PRIMITIVE, WANDDER_TAG_ENUM,
                p->itemptr, p->itemlen,
                &ptr, &rem, child);
    }


    /* gprs operation error code (22)  -- optional */
    lookup = WANDDER_UMTSIRI_CONTENTS_GPRS_ERROR_CODE;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        encode_here_ber_update(
                22, WANDDER_CLASS_CONTEXT_PRIMITIVE, WANDDER_TAG_OCTETSTRING,
                p->itemptr, p->itemlen,
                &ptr, &rem, child);
    }

    /* IRI version (23) */
    encode_here_ber_update(
                23, WANDDER_CLASS_CONTEXT_PRIMITIVE, WANDDER_TAG_ENUM,
                &iriversion, sizeof(iriversion),
                &ptr, &rem, child);

    /* networkIdentifier (26) -- nested */
    preencoded_here(&ptr, &rem, WANDDER_PREENCODE_CSEQUENCE_26, child);

    lookup = WANDDER_UMTSIRI_CONTENTS_OPERATOR_IDENTIFIER;
    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        encode_here_ber_update(
                0, WANDDER_CLASS_CONTEXT_PRIMITIVE, WANDDER_TAG_OCTETSTRING,
                p->itemptr, p->itemlen,
                &ptr, &rem, child);
    } else {
        fprintf(stderr, "wandder: warning, no operator identifier available for constructing UMTS IRI\n");
        fprintf(stderr, "wandder: UMTS IRI record may be invalid...\n");
    }

    lookup = WANDDER_UMTSIRI_CONTENTS_GGSN_IPADDRESS;

    HASH_FIND(hh, params, &lookup, sizeof(lookup), p);
    if (p) {
        preencoded_here(&ptr, &rem, WANDDER_PREENCODE_CSEQUENCE_1, child);
        preencoded_here(&ptr, &rem, WANDDER_PREENCODE_CSEQUENCE_5, child);
        encode_ipaddress_inplace(&ptr, &rem, child, (wandder_etsili_ipaddress_t *)(p->itemptr));
        ENDCONSTRUCTEDBLOCK(ptr,2)
    } else {
        fprintf(stderr, "wandder: warning, no network element identifier available for constructing UMTS IRI\n");
        fprintf(stderr, "wandder: UMTS IRI record may be invalid...\n");
    }

    //ensure there is enough space for the last section
    child->body.data = data_ptr_diff + child->buf;
    ptr += check_body_size(child, (ptr - child->body.buf) + (8*2));
    ENDCONSTRUCTEDBLOCK(ptr,8) //endseq
    child->body.len = ptr - child->body.buf;
    child->len = ptr - child->buf;

}

void wandder_init_etsili_umtsiri(
        wandder_encoder_ber_t* enc_ber,
        wandder_etsili_top_t* top) {

    wandder_encoded_result_ber_t* res_ber;

    if (!top || !top->preencoded || !enc_ber){
        fprintf(stderr,"Make sure wandder_encode_init_top_ber is called first\n");
        return;
    }
    
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_2]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_0]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_USEQUENCE]);

    ptrdiff_t iri_diff = enc_ber->ptr - enc_ber->buf;

    // most of UMTSIRI is regenerated, so no point continuing to
    // populate areas that might be over written
    ptrdiff_t params_diff = enc_ber->ptr - enc_ber->buf;

    res_ber = wandder_encode_finish_ber(enc_ber);

    top->umtsiri.buf              = res_ber->buf;
    top->umtsiri.len              = res_ber->len;
    top->umtsiri.alloc_len        = res_ber->len;
    top->umtsiri.meta             = res_ber->buf + iri_diff;
    top->umtsiri.data             = res_ber->buf + params_diff;

    free(res_ber);

}

wandder_etsili_child_t *wandder_etsili_create_child(wandder_etsili_top_t* top, 
        wandder_generic_body_t * body) {

    ptrdiff_t diff;
    wandder_etsili_child_t * child;

    //ensure top and body exist
    if ( !(top) || !(top->header.buf) ) {
        fprintf(stderr,
            "Make sure wandder_encode_init_top_ber have been called first\n");
        return NULL;
    }
    if (!body->buf) {
        fprintf(stderr,
            "Make sure wandder_init_etsili_??? have been called first\n");
        return NULL;
    }
    
    child = malloc(sizeof(wandder_etsili_child_t));
    child->len = top->header.len + body->len;
    child->buf = malloc(child->len);
    child->alloc_len = child->len;

    child->owner = top;
    child->flist = body->flist;
    if (child->flist) {
        if (pthread_mutex_lock(&(child->flist->mutex)) == 0) {
            child->flist->counter++;
        pthread_mutex_unlock(&(child->flist->mutex));
        }
    }

    child->header.buf = child->buf;
    child->header.len = top->header.len;

    memcpy(child->header.buf, top->header.buf, top->header.len);

    diff = child->header.buf - top->header.buf;
    child->header.cin   = diff + top->header.cin;
    child->header.seqno = diff + top->header.seqno;
    child->header.sec   = diff + top->header.sec;
    child->header.usec  = diff + top->header.usec;
    child->header.end   = diff + top->header.end;


    //TODO potential to make header/body into one buffer 
    ///as header size is const
    child->body.buf = child->header.buf + child->header.len; 

    child->body.alloc_len = body->len; 
    //this length is the alloc from the start of the body

    memcpy(child->body.buf, body->buf, body->len);
    child->body.len = body->len;

    diff = child->body.buf - body->buf;
    child->body.meta = diff + body->meta;
    child->body.data = diff + body->data;

    return child;

}

void wandder_free_child(wandder_etsili_child_t * child){

    if (child) {
        if (child->flist){
            if (pthread_mutex_lock(&(child->flist->mutex)) == 0) {
                if (child->flist->marked_for_delete == 0){
                    //release and return
                    child->nextfree = child->flist->first;
                    child->flist->first = child;

                    pthread_mutex_unlock(&(child->flist->mutex));
                    return;
                }

                child->flist->counter--;
                
                if (child->flist->counter == 0){
                    //we are the sole owner so we can free it
                    pthread_mutex_destroy(&(child->flist->mutex));
                    free(child->flist);
                } else {
                    pthread_mutex_unlock(&(child->flist->mutex));
                }
            }
        }

        if (child->buf)
            free(child->buf);
        
        free(child);
    }
}

void wandder_init_etsili_ipmmcc(
        wandder_encoder_ber_t* enc_ber,
        wandder_etsili_top_t* top) {

    uint32_t frametype = 0;
    uint32_t mmccproto = 0;

    wandder_encoded_result_ber_t* res_ber;

    if (!top || !top->preencoded || !enc_ber){
        fprintf(stderr,"Make sure wandder_encode_init_top_ber is called first\n");
        return;
    }
    
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_2]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_1]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_USEQUENCE]);

    ptrdiff_t dir_diff = enc_ber->ptr - enc_ber->buf;

    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_DIRFROM]);


    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_2]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_12]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_IPMMCCOID]);

    ptrdiff_t ipcontent_diff = enc_ber->ptr - enc_ber->buf;
    wandder_encode_next_ber(enc_ber, WANDDER_TAG_IPPACKET,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, NULL, 0);

    wandder_encode_next_ber(enc_ber, WANDDER_TAG_ENUM,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, &frametype,
                sizeof frametype);

    wandder_encode_next_ber(enc_ber, WANDDER_TAG_ENUM,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, &mmccproto,
                sizeof mmccproto);

    wandder_encode_endseq_ber(enc_ber, 6);

    res_ber = wandder_encode_finish_ber(enc_ber);

    top->ipmmcc.buf                 = res_ber->buf;
    top->ipmmcc.len                 = res_ber->len;
    top->ipmmcc.alloc_len           = res_ber->len;
    top->ipmmcc.meta                = res_ber->buf + dir_diff;
    top->ipmmcc.data                = res_ber->buf + ipcontent_diff;

    free(res_ber);

    return;
}

void wandder_init_etsili_ipmmiri(
        wandder_encoder_ber_t* enc_ber,
        wandder_etsili_top_t* top) {

    wandder_encoded_result_ber_t* res_ber;
    uint32_t source_ip = 0;
    uint32_t dest_ip = 0;
    uint8_t *ipsrc = (uint8_t*)&source_ip;
    uint8_t *ipdest = (uint8_t*)&dest_ip;
    wandder_etsili_iri_type_t iritype = 0;

    if (!top || !top->preencoded || !enc_ber){
        fprintf(stderr,"Make sure wandder_encode_init_top_ber is called first\n");
        return;
    }

    wandder_etsili_ipaddress_t encipsrc, encipdst;
   
    encipsrc.iptype = WANDDER_IPADDRESS_VERSION_4;
    encipsrc.assignment = WANDDER_IPADDRESS_ASSIGNED_UNKNOWN;
    encipsrc.v6prefixlen = 0;
    encipsrc.v4subnetmask = 0xffffffff;
    encipsrc.valtype = WANDDER_IPADDRESS_REP_BINARY;
    encipsrc.ipvalue = malloc(sizeof(uint32_t));
    memcpy(encipsrc.ipvalue, &ipsrc, sizeof(uint32_t));

    encipdst = encipsrc;
    encipdst.ipvalue = malloc(sizeof(uint32_t));
    memcpy(encipdst.ipvalue, &ipdest, sizeof(uint32_t));

    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_2]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_0]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_USEQUENCE]);

    ptrdiff_t iri_diff = enc_ber->ptr - enc_ber->buf;
    wandder_encode_next_ber(enc_ber, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &iritype,
            sizeof iritype);

    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_2]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_11]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_IPMMIRIOID]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_1]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_1]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_0]);
    
    //encode ip address encipsrc
    encode_ipaddress(enc_ber, &encipsrc);
    wandder_encode_endseq_ber(enc_ber, 1);

    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_1]);

    //encode ip address encipdst
    encode_ipaddress(enc_ber, &encipdst);
    wandder_encode_endseq_ber(enc_ber, 1);

    ptrdiff_t ipcontent_diff = enc_ber->ptr - enc_ber->buf;
    wandder_encode_next_ber(enc_ber, WANDDER_TAG_IPPACKET,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, NULL, 0);


    wandder_encode_endseq_ber(enc_ber, 8);

    res_ber = wandder_encode_finish_ber(enc_ber);

    top->ipmmiri.buf               = res_ber->buf;
    top->ipmmiri.len               = res_ber->len;
    top->ipmmiri.alloc_len         = res_ber->len;
    top->ipmmiri.meta              = res_ber->buf + iri_diff;
    top->ipmmiri.data              = res_ber->buf + ipcontent_diff;

    free(res_ber);

    return;
}

void wandder_init_etsili_ipcc(
        wandder_encoder_ber_t* enc_ber,
        wandder_etsili_top_t* top) {

    if (!top || !top->preencoded || !enc_ber){
        fprintf(stderr,"Make sure wandder_encode_init_top_ber is called first\n");
        return;
    }

    wandder_encoded_result_ber_t* res_ber;
    
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_2]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_1]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_USEQUENCE]);

    ptrdiff_t dir_diff = enc_ber->ptr - enc_ber->buf;
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_DIRFROM]);


    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_2]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_2]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_IPCCOID]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_1]);

    ptrdiff_t ipcontent_diff = enc_ber->ptr - enc_ber->buf;
    wandder_encode_next_ber(enc_ber, WANDDER_TAG_IPPACKET,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, NULL, 0);

    wandder_encode_endseq_ber(enc_ber, 7);

    res_ber = wandder_encode_finish_ber(enc_ber);

    top->ipcc.buf               = res_ber->buf;
    top->ipcc.len               = res_ber->len;
    top->ipcc.alloc_len         = res_ber->len;
    top->ipcc.meta              = res_ber->buf + dir_diff;
    top->ipcc.data              = res_ber->buf + ipcontent_diff;

    free(res_ber);

    return;
}

void wandder_init_etsili_ipiri(
        wandder_encoder_ber_t* enc_ber,
        wandder_etsili_top_t* top) {

    wandder_encoded_result_ber_t* res_ber;
    wandder_etsili_iri_type_t iritype = 0;

    if (!top || !top->preencoded || !enc_ber){
        fprintf(stderr,"Make sure wandder_encode_init_top_ber is called first\n");
        return;
    }

    //////////////////////////////////////////////////////////////// block 0
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_2]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_0]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_USEQUENCE]);
    //////////////////////////////////////////////////////////////// dir

    ptrdiff_t iri_diff = enc_ber->ptr - enc_ber->buf;
    wandder_encode_next_ber(enc_ber, WANDDER_TAG_ENUM,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &iritype,
                sizeof (iritype));

    //////////////////////////////////////////////////////////////// block 1
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_2]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_2]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_IPIRIOID]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_1]);
    //////////////////////////////////////////////////////////////// ipcontents
    ptrdiff_t params_diff = enc_ber->ptr - enc_ber->buf;
    wandder_encode_endseq_ber(enc_ber, 7); //endseq

    res_ber = wandder_encode_finish_ber(enc_ber);

    top->ipiri.buf              = res_ber->buf;
    top->ipiri.len              = res_ber->len;
    top->ipiri.alloc_len        = res_ber->len;
    top->ipiri.meta             = res_ber->buf + iri_diff;
    top->ipiri.data             = res_ber->buf + params_diff;

    free(res_ber);

    return;
}

void wandder_init_etsili_umtscc(
        wandder_encoder_ber_t* enc_ber,
        wandder_etsili_top_t* top) {

    if (!top || !top->preencoded || !enc_ber){
        fprintf(stderr,"Make sure wandder_encode_init_top_ber is called first\n");
        return;
    }

    wandder_encoded_result_ber_t* res_ber;
    
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_2]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_1]);
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_USEQUENCE]);

    ptrdiff_t dir_diff = enc_ber->ptr - enc_ber->buf;
    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_DIRFROM]);


    wandder_append_preencoded_ber(enc_ber, 
            top->preencoded[WANDDER_PREENCODE_CSEQUENCE_2]);
    
    ptrdiff_t ipcontent_diff = enc_ber->ptr - enc_ber->buf;
    wandder_encode_next_ber(enc_ber, WANDDER_TAG_IPPACKET,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, NULL, 0);

    wandder_encode_endseq_ber(enc_ber, 5);

    res_ber = wandder_encode_finish_ber(enc_ber);

    top->umtscc.buf               = res_ber->buf;
    top->umtscc.len               = res_ber->len;
    top->umtscc.alloc_len         = res_ber->len;
    top->umtscc.meta              = res_ber->buf + dir_diff;
    top->umtscc.data              = res_ber->buf + ipcontent_diff;

    free(res_ber);

    return;
}

void wandder_encode_etsi_ipmmcc_ber (
        int64_t cin, int64_t seqno,
        struct timeval* tv, void* ipcontents, size_t iplen, uint8_t dir,
        wandder_etsili_child_t * child) {
    
    if (!child || !child->header.buf) {
        //error out for not initlizing top first
        fprintf(stderr,"Make sure wandder_encode_init_top_ber is called first\n");
        return;
    }
    if (!child->body.buf) {
        //error out for not initlizing ipmmcc
        fprintf(stderr,"Call init ipmmcc first.\n");
        return;
    }

    update_etsili_pshdr_pc(&child->header, cin, seqno, tv);
    update_etsili_ipmmcc(ipcontents, iplen, dir, child);

}

void wandder_encode_etsi_ipmmiri_ber (
        int64_t cin, int64_t seqno,
        struct timeval* tv, void* ipcontents, size_t iplen, 
        wandder_etsili_iri_type_t iritype,
        uint8_t *ipsrc, uint8_t *ipdest, int ipfamily,
        wandder_etsili_child_t * child) {


    if (!child || !child->header.buf) {
        //error out for not initlizing top first
        fprintf(stderr,"Make sure wandder_encode_init_top_ber is called first\n");
        return;
    }
    if (!child->body.buf) {
        //error out for not initlizing ipmmiri
        fprintf(stderr,"Call init ipmmiri first.\n");
        return;
    }

    update_etsili_pshdr_pc(&child->header, cin, seqno, tv);
    update_etsili_ipmmiri(ipcontents, iplen, iritype, child);

}

void wandder_encode_etsi_ipcc_ber (
        int64_t cin, int64_t seqno,
        struct timeval* tv, void* ipcontents, size_t iplen, uint8_t dir,
        wandder_etsili_child_t * child) {

    if (!child || !child->header.buf) {
        //error out for not initlizing top first
        fprintf(stderr,"Make sure wandder_encode_init_top_ber is called first\n");
        return;
    }
    if (!child->body.buf) {
        //error out for not initlizing ipcc
        fprintf(stderr,"Call init ipcc first.\n");
        return;
    }
    
    update_etsili_pshdr_pc(&child->header, cin, seqno, tv);
    update_etsili_ipcc(ipcontents, iplen, dir, child);

}

void wandder_encode_etsi_ipiri_ber (
        int64_t cin, int64_t seqno,
        struct timeval* tv, void* params, wandder_etsili_iri_type_t iritype,
        wandder_etsili_child_t * child) {
    
    if (!child || !child->header.buf) {
        //error out for not initlizing top first
        fprintf(stderr,"Make sure wandder_encode_init_top_ber is called first\n");
        return;
    }
    if (!child->body.buf) {
        //error out for not initlizing ipiri
        fprintf(stderr,"Call init ipiri first.\n");
        return;
    }

    update_etsili_pshdr_pc(&child->header, cin, seqno, tv);
    update_etsili_ipiri(params, iritype, child);

}

void wandder_encode_etsi_umtsiri_ber(
        int64_t cin, int64_t seqno,
        struct timeval* tv, void* params, wandder_etsili_iri_type_t iritype,
        wandder_etsili_child_t * child) {
    
    if (!child || !child->header.buf) {
        //error out for not initlizing top first
        fprintf(stderr,"Make sure wandder_encode_init_top_ber is called first\n");
        return;
    }
    if (!child->body.buf) {
        //error out for not initlizing umtsiri
        fprintf(stderr,"Call init umtsiri first.\n");
        return;
    }

    update_etsili_pshdr_pc(&child->header, cin, seqno, tv);
    update_etsili_umtsiri(params, iritype, child);
}

void wandder_encode_etsi_umtscc_ber (
        int64_t cin, int64_t seqno,
        struct timeval* tv, void* ipcontents, size_t iplen, uint8_t dir,
        wandder_etsili_child_t * child) {

    if (!child || !child->header.buf) {
        //error out for not initlizing top first
        fprintf(stderr,"Make sure wandder_encode_init_top_ber is called first\n");
        return;
    }
    if (!child->body.buf) {
        //error out for not initlizing umtscc
        fprintf(stderr,"Call init umtscc first.\n");
        return;
    }
    
    update_etsili_pshdr_pc(&child->header, cin, seqno, tv);
    update_etsili_umtscc(ipcontents, iplen, dir, child);

}

wandder_etsili_top_t* wandder_encode_init_top_ber (wandder_encoder_ber_t* enc_ber, 
        wandder_etsili_intercept_details_t* intdetails) {

    wandder_etsili_top_t* top = calloc(sizeof(wandder_etsili_top_t), 1);

    top->preencoded =  wandder_etsili_preencode_static_fields_ber(intdetails);

    init_etsili_pshdr_pc(enc_ber, top);

    top->increment_len = enc_ber->increment;

    return top;
}

wandder_etsili_child_freelist_t *wandder_create_etsili_child_freelist() {
    wandder_etsili_child_freelist_t *flist;

    pthread_mutexattr_t attr;

    flist = (wandder_etsili_child_freelist_t *)calloc(1,
            sizeof(wandder_etsili_child_freelist_t));

    //setting recursive as lock operations happen across a linked list
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&(flist->mutex), &attr);
    flist->first = NULL;
    return flist;
}

wandder_etsili_child_t *wandder_create_etsili_child(
        wandder_etsili_top_t* top, 
        wandder_generic_body_t * body) {

    wandder_etsili_child_t *child = NULL;

    //only need to actually create child if none exist here

    if (pthread_mutex_trylock(&(body->flist->mutex)) == 0) {
        //if you cant obtain mutex just make a new child, no need to wait
        if (body->flist->first) {
            child = body->flist->first;
            body->flist->first = child->nextfree;
        }

        pthread_mutex_unlock(&(body->flist->mutex));
    }

    if (child == NULL) {
        child = wandder_etsili_create_child(top, body);
    }

    return child;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
