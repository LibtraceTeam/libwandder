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

const uint8_t etsi_lipsdomainid[9] = {
        0x00, 0x04, 0x00, 0x02, 0x02, 0x05, 0x01, 0x11};

uint8_t etsi_ipccoid[4] = {0x05, 0x03, 0x0a, 0x02};
uint8_t etsi_ipirioid[4] = {0x05, 0x03, 0x0a, 0x01};
uint8_t etsi_ipmmccoid[4] = {0x05, 0x05, 0x06, 0x02};
uint8_t etsi_ipmmirioid[4] = {0x05, 0x05, 0x06, 0x01};

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
    etsidec->dec = NULL;

    return etsidec;
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
    /* Find IPCCContents or IPMMCCContents or UMTSCC */
    wandder_reset_decoder(etsidec->dec);
    wandder_found_t *found = NULL;
    wandder_target_t cctgts[3];

    cctgts[0].parent = &etsidec->ipcccontents;
    cctgts[0].itemid = 0;
    cctgts[0].found = false;

    cctgts[1].parent = &etsidec->ipmmcc;
    cctgts[1].itemid = 1;
    cctgts[1].found = false;

    cctgts[2].parent = &etsidec->cccontents;
    cctgts[2].itemid = 4;
    cctgts[2].found = false;

    *len = 0;
    if (wandder_search_items(etsidec->dec, 0, &(etsidec->root), cctgts, 3,
                &found, 1) > 0) {
        *len = found->list[0].item->length;
        vp = found->list[0].item->valptr;

        if (found->list[0].targetid == 0) {
            strncpy(name, etsidec->ipcccontents.members[0].name, namelen);
        } else if (found->list[0].targetid == 1) {
            strncpy(name, etsidec->ipmmcc.members[1].name, namelen);
        } else if (found->list[0].targetid == 2) {
            strncpy(name, etsidec->cccontents.members[4].name, namelen);
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
        fprintf(stderr, "Unexpected IP address length: %lu\n", item->length);
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
    free(dec->cid.members);
    free(dec->msts.members);
    free(dec->cccontents.members);
    free(dec->ccpayload.members);
    free(dec->operatorleamessage.members);
    free(dec->option.members);
    free(dec->optionreq.members);
    free(dec->optionresp.members);
    free(dec->integritycheck.members);
    free(dec->tripayload.members);
    free(dec->ipiriid.members);
    free(dec->ipiricontents.members);
    free(dec->ipiri.members);
    free(dec->umtsiri.members);
    free(dec->umtsiri_params.members);
    free(dec->iricontents.members);
    free(dec->iripayload.members);
    free(dec->payload.members);
    free(dec->psheader.members);
    free(dec->pspdu.members);

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
                .descend = NULL,
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

    dec->iricontents.membercount = 16;
    ALLOC_MEMBERS(dec->iricontents);
    dec->iricontents.members[0] = WANDDER_NOACTION;
    dec->iricontents.members[1] =     // TODO
        (struct wandder_dump_action) {
                .name = "emailIRI",
                .descend = NULL,
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
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->payload.members[4] =        // TODO?
        (struct wandder_dump_action) {
                .name = "encryptionContainer",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };

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
}


/////////////////////////////////start of BER code

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
        if (top->ipcc.buf)
            free(top->ipcc.buf);
        if (top->ipmmcc.buf)
            free(top->ipmmcc.buf);
        if (top->ipiri.buf)
            free(top->ipiri.buf);
        if (top->ipmmiri.buf)
            free(top->ipmmiri.buf);
        free(top);
    }
}

wandder_buf_t ** wandder_etsili_preencode_static_fields_ber(
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

    pendarray[WANDDER_PREENCODE_CSEQUENCE_7] =  wandder_encode_new_ber(
            WANDDER_CLASS_CONTEXT_CONSTRUCT, 
            7,
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

static ptrdiff_t check_body_size(wandder_generic_body_t * body, size_t currlen){
    
    uint8_t* new;
    ptrdiff_t offset = 0;

    if (currlen + (body->data - body->buf) > body->alloc_len){
        body->alloc_len = body->len + 128; //TODO magic value should be from increment length
        new = realloc(body->buf, body->alloc_len);
        if (new == NULL){
            //TODO handle realloc fail
            printf("unable to alloc mem\n");
            assert(0);
        }
        
        //update all refrences
        if (new != body->buf){ //only need to update if alloc moved
            ptrdiff_t offset = (new - body->buf);
            body->buf += offset;
            body->meta += offset; 
            body->data += offset;
            return offset;
        }
    }
    return offset;
}

static uint8_t* wandder_encode_body_data_ber(
        wandder_generic_body_t* body,
        uint8_t class, 
        uint8_t idnum, 
        uint8_t encodeas, 
        uint8_t * valptr,
        size_t vallen){

    uint8_t* new;
    ptrdiff_t currlen = calculate_length(idnum, class, encodeas, vallen); 
    
    //if new length cannot fit in old space make more
    // if currlen+(currptr-baseptr) > alloclen
    check_body_size(body, currlen);

    ptrdiff_t rem = body->alloc_len - (body->data - body->buf);

    size_t ret = encode_here_ber(idnum, class, encodeas, valptr, vallen, 
            body->data, rem);

    return ret + body->data;
}

static void update_etsili_pshdr_pc(wandder_etsili_top_t* top, int64_t cin,
        int64_t seqno, struct timeval* tv){

    ber_rebuild_integer(
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            1, 
            &(cin), 
            sizeof cin,
            top->header.cin);

    ber_rebuild_integer(
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            4, 
            &(seqno), 
            sizeof seqno,
            top->header.seqno);

    ber_rebuild_integer(
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0, 
            &(tv->tv_sec), 
            sizeof tv->tv_sec,
            top->header.sec);

    ber_rebuild_integer(
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            1, 
            &(tv->tv_usec), 
            sizeof tv->tv_usec,
            top->header.usec);
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
        wandder_etsili_top_t* top) {
    if (dir == 0) {
        memcpy(top->ipcc.meta, 
                top->preencoded[WANDDER_PREENCODE_DIRFROM]->buf, 
                top->preencoded[WANDDER_PREENCODE_DIRFROM]->len);
    } else if (dir == 1) {
        memcpy(top->ipcc.meta, 
                top->preencoded[WANDDER_PREENCODE_DIRTO]->buf, 
                top->preencoded[WANDDER_PREENCODE_DIRTO]->len);
    } else if (dir == 2) {
        memcpy(top->ipcc.meta, 
                top->preencoded[WANDDER_PREENCODE_DIRUNKNOWN]->buf, 
                top->preencoded[WANDDER_PREENCODE_DIRUNKNOWN]->len);
    } else {
        ber_rebuild_integer(
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0, 
            &(dir), 
            sizeof dir,
            top->ipcc.meta);
    }

    uint8_t* ptr = wandder_encode_body_data_ber(
            &(top->ipcc),
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_IPPACKET,
            ipcontents, 
            iplen);

    ptr += check_body_size(&top->ipcc, (ptr - top->ipcc.buf) + (7*2));
    ENDCONSTRUCTEDBLOCK(ptr,7)
    top->ipcc.len = ptr - top->ipcc.buf;

}

static void update_etsili_ipmmcc(
        void* ipcontents, size_t iplen, uint8_t dir, 
        wandder_etsili_top_t* top) {

    uint32_t frametype = 0; //TODO these are hard coded to 0? 
    uint32_t mmccproto = 0; //at least they are in etsili_core.c in OpenLI

    if (dir == 0) {
        memcpy(top->ipcc.meta, 
                top->preencoded[WANDDER_PREENCODE_DIRFROM]->buf, 
                top->preencoded[WANDDER_PREENCODE_DIRFROM]->len);
    } else if (dir == 1) {
        memcpy(top->ipcc.meta, 
                top->preencoded[WANDDER_PREENCODE_DIRTO]->buf, 
                top->preencoded[WANDDER_PREENCODE_DIRTO]->len);
    } else if (dir == 2) {
        memcpy(top->ipcc.meta, 
                top->preencoded[WANDDER_PREENCODE_DIRUNKNOWN]->buf, 
                top->preencoded[WANDDER_PREENCODE_DIRUNKNOWN]->len);
    } else {
        ber_rebuild_integer(
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0, 
            &(dir), 
            sizeof dir,
            top->ipcc.meta);
    }

    uint8_t* ptr = wandder_encode_body_data_ber(
            &(top->ipmmcc),
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            1,
            WANDDER_TAG_IPPACKET,
            ipcontents, 
            iplen);

    //ensure there is enough space for the last section
    ptr += check_body_size(&top->ipmmcc, (ptr - top->ipmmcc.buf) +
            (6*2) + (top->preencoded[WANDDER_PREENCODE_DIRUNKNOWN]->len *2));

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
    top->ipmmcc.len = ptr - top->ipmmcc.buf;
}

static void update_etsili_ipmmiri(
        void* ipcontents, size_t iplen, wandder_etsili_iri_type_t iritype, 
        wandder_etsili_top_t* top) {

    ber_rebuild_integer(
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0, 
            &(iritype), 
            sizeof iritype,
            top->ipmmiri.meta);

    uint8_t* ptr = wandder_encode_body_data_ber(
            &(top->ipmmiri),
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            2,
            WANDDER_TAG_IPPACKET,
            ipcontents, 
            iplen);

    //ensure there is enough space for the last section
    ptr += check_body_size(&top->ipmmiri, (ptr - top->ipmmiri.buf) + (8*2));
    ENDCONSTRUCTEDBLOCK(ptr,8)
    top->ipmmiri.len = ptr - top->ipmmiri.buf;
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

static void update_etsili_ipiri(
        wandder_etsili_generic_t *params, wandder_etsili_iri_type_t iritype, 
        wandder_etsili_top_t* top) {

    wandder_etsili_generic_t *p, *tmp;
    wandder_ipiri_id_t* iriid;
    size_t ret;
    uint8_t * ptr = top->ipiri.data;
    ptrdiff_t data_ptr_diff = ptr - top->ipiri.buf;
    ptrdiff_t rem = (ptr - top->ipiri.buf) - top->ipiri.alloc_len;
    
    ber_rebuild_integer(
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0, 
            &(iritype), 
            sizeof iritype,
            top->ipiri.meta);

    //do params here from
    HASH_SRT(hh, params, sort_etsili_generic);
    HASH_ITER(hh, params, p, tmp) {
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
                ret = encode_here_ber(
                        p->itemnum,
                        WANDDER_CLASS_CONTEXT_CONSTRUCT,
                        WANDDER_TAG_SEQUENCE,
                        p->itemptr,
                        p->itemlen, 
                        ptr, rem);
                ptr += ret;
                rem -= ret;
                ENDCONSTRUCTEDBLOCK(ptr, 1)
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
    top->ipiri.data = data_ptr_diff + top->ipiri.buf;
    ptr += check_body_size(&(top->ipiri), (ptr - top->ipiri.buf) + (8*2));
    ENDCONSTRUCTEDBLOCK(ptr,8) //endseq
    top->ipiri.len = ptr - top->ipiri.buf;

}

void wandder_init_etsili_ipmmcc(
        wandder_encoder_ber_t* enc_ber,
        wandder_etsili_top_t* top) {

    uint32_t frametype = 0;
    uint32_t mmccproto = 0;

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

    wandder_etsili_ipaddress_t encipsrc, encipdst;
   
    encipsrc.iptype = WANDDER_IPADDRESS_VERSION_4;
    encipsrc.assignment = WANDDER_IPADDRESS_ASSIGNED_UNKNOWN;
    encipsrc.v6prefixlen = 0;
    encipsrc.v4subnetmask = 0xffffffff;
    encipsrc.valtype = WANDDER_IPADDRESS_REP_BINARY;
    encipsrc.ipvalue = ipsrc;

    encipdst = encipsrc;
    encipdst.ipvalue = ipdest;

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
}

void wandder_init_etsili_ipcc(
        wandder_encoder_ber_t* enc_ber,
        wandder_etsili_top_t* top) {

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
    top->ipcc.meta               = res_ber->buf + dir_diff;
    top->ipcc.data         = res_ber->buf + ipcontent_diff;

    free(res_ber);
}

void wandder_init_etsili_ipiri(
        wandder_encoder_ber_t* enc_ber,
        wandder_etsili_top_t* top) {

    wandder_encoded_result_ber_t* res_ber;
    wandder_etsili_generic_t *p, *tmp;
    wandder_ipiri_id_t* iriid;
    wandder_etsili_iri_type_t iritype = 0;

    
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
}

void wandder_encode_etsi_ipmmcc_ber (
        int64_t cin, int64_t seqno,
        struct timeval* tv, void* ipcontents, size_t iplen, uint8_t dir,
        wandder_etsili_top_t* top) {
    
    if (!top || !top->header.buf) {
        //error out for not initlizing top first
        printf("Call init top first.\n");
        return;
    }
    if (!top->ipmmcc.buf) {
        //error out for not initlizing ipmmcc
        printf("Call init ipmmcc first.\n");
        return;
    }

    update_etsili_pshdr_pc(top, cin, seqno, tv);
    update_etsili_ipmmcc(ipcontents, iplen, dir, top);

}

void wandder_encode_etsi_ipmmiri_ber (
        int64_t cin, int64_t seqno,
        struct timeval* tv, void* ipcontents, size_t iplen, 
        wandder_etsili_iri_type_t iritype,
        uint8_t *ipsrc, uint8_t *ipdest, int ipfamily,
        wandder_etsili_top_t* top) {


    if (!top || !top->header.buf) {
        //error out for not initlizing top first
        printf("Call init top first.\n");
        return;
    }
    if (!top->ipmmiri.buf) {
        //error out for not initlizing ipmmiri
        printf("Call init ipmmiri first.\n");
        return;
    }

    update_etsili_pshdr_pc(top, cin, seqno, tv);
    update_etsili_ipmmiri(ipcontents, iplen, iritype, top);

}

void wandder_encode_etsi_ipcc_ber (
        int64_t cin, int64_t seqno,
        struct timeval* tv, void* ipcontents, size_t iplen, uint8_t dir,
        wandder_etsili_top_t* top) {

    if (!top || !top->header.buf) {
        //error out for not initlizing top first
        printf("Call init top first.\n");
        return;
    }
    if (!top->ipcc.buf) {
        //error out for not initlizing ipcc
        printf("Call init ipcc first.\n");
        return;
    }
    
    update_etsili_pshdr_pc(top, cin, seqno, tv);
    update_etsili_ipcc(ipcontents, iplen, dir, top);

}

void wandder_encode_etsi_ipiri_ber (
        int64_t cin, int64_t seqno,
        struct timeval* tv, void* params, wandder_etsili_iri_type_t iritype,
        wandder_etsili_top_t* top) {
    
    if (!top || !top->header.buf) {
        //error out for not initlizing top first
        printf("Call init top first.\n");
        return;
    }
    if (!top->ipiri.buf) {
        //error out for not initlizing ipiri
        printf("Call init ipiri first.\n");
        return;
    }

    update_etsili_pshdr_pc(top, cin, seqno, tv);
    update_etsili_ipiri(params, iritype, top);

}

wandder_etsili_top_t* wandder_encode_init_top_ber (wandder_encoder_ber_t* enc_ber, 
        wandder_etsili_intercept_details_t* intdetails) {
    
    struct timeval tv = {0,0};


    wandder_etsili_top_t* top = calloc(sizeof(wandder_etsili_top_t), 1);

    top->preencoded =  wandder_etsili_preencode_static_fields_ber(intdetails);

    init_etsili_pshdr_pc(enc_ber, top);

    top->increment_len = enc_ber->increment;

    return top;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
