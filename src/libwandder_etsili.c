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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include "libwandder_etsili.h"

wandder_dumper_t ipaddress;
wandder_dumper_t ipvalue;
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
wandder_dumper_t integritycheck;
wandder_dumper_t inclseqnos;
wandder_dumper_t option;
wandder_dumper_t optionseq;
wandder_dumper_t optionreq;
wandder_dumper_t optionresp;
wandder_dumper_t operatorleamessage;
wandder_dumper_t tripayload;
wandder_dumper_t payload;
wandder_dumper_t psheader;
wandder_dumper_t pspdu;
wandder_dumper_t ipcc;
wandder_dumper_t ipcccontents;
wandder_dumper_t iripayloadseq;

static int init_called = 0;

static void init_dumpers(wandder_etsispec_t *dec);
static void free_dumpers(wandder_etsispec_t *dec);
static char *interpret_enum(wandder_etsispec_t *etsidec, wandder_item_t *item,
        wandder_dumper_t *curr, char *valstr, int len);

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
    uint16_t savedlevel = 0;


    tv.tv_sec = 0;
    tv.tv_usec = 0;
    if (etsidec->decstate == 0) {
        fprintf(stderr, "No buffer attached to this decoder -- please call"
                "wandder_attach_etsili_buffer() first!\n");
        return tv;
    }

    /* Find PSHeader */
    wandder_reset_decoder(etsidec->dec);
    wandder_found_t *found = NULL;
    wandder_target_t pshdrtgt = {&(etsidec->pspdu), 1, false};

    if (wandder_search_items(etsidec->dec, 0, &(etsidec->root), &pshdrtgt, 1,
                &found, 1) == 0) {
        return tv;
    }

    /* dec->current should be pointing right at PSHeader */
    savedlevel = wandder_get_level(etsidec->dec);

    wandder_decode_next(etsidec->dec);
    while (wandder_get_level(etsidec->dec) > savedlevel) {
        if (wandder_get_identifier(etsidec->dec) == 5) {
            tv = wandder_generalizedts_to_timeval(
                    wandder_get_itemptr(etsidec->dec),
                    wandder_get_itemlen(etsidec->dec));
            break;
        }
        if (wandder_get_identifier(etsidec->dec) == 7) {
            printf("got msts field, please write a parser for it!\n");

            /* TODO parse msts field */
            break;
        }
        wandder_decode_next(etsidec->dec);
    }
    wandder_free_found(found);
    return tv;

}

uint32_t wandder_etsili_get_pdu_length(wandder_etsispec_t *etsidec) {

    if (etsidec->decstate == 0) {
        fprintf(stderr, "No buffer attached to this decoder -- please call"
                "wandder_attach_etsili_buffer() first!\n");
        return 0;
    }
    /* Easy, reset the decoder then grab the length of the first element */
    wandder_reset_decoder(etsidec->dec);

    if (wandder_decode_next(etsidec->dec) <= 0) {
        return 0;
    }

    /* Don't forget to include the preamble length so the caller can skip
     * over the entire PDU if desired.
     */
    return wandder_get_itemlen(etsidec->dec) +
            etsidec->dec->current->preamblelen;
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

    switch(wandder_get_class(etsidec->dec)) {

        case WANDDER_CLASS_CONTEXT_PRIMITIVE:
            ident = wandder_get_identifier(etsidec->dec);
            (etsidec->stack->atthislevel[etsidec->stack->current])++;

            if (curr->members[ident].interpretas == WANDDER_TAG_IPPACKET) {
                /* Reached the actual IP contents  -- stop */
                return NULL;
            }

            if (curr->members[ident].interpretas == WANDDER_TAG_ENUM) {
                if (interpret_enum(etsidec, etsidec->dec->current, curr,
                            valstr, 2048) == NULL) {
                    fprintf(stderr, "Failed to interpret field %d:%d\n",
                            etsidec->stack->current, ident);
                    return NULL;
                }
            } else {
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
        uint32_t *len) {
    uint8_t *vp = NULL;

    if (etsidec->decstate == 0) {
        fprintf(stderr, "No buffer attached to this decoder -- please call"
                "wandder_attach_etsili_buffer() first!\n");
        return NULL;
    }
    /* Find IPCCContents */
    wandder_reset_decoder(etsidec->dec);
    wandder_found_t *found = NULL;
    wandder_target_t ipcctgt = {&etsidec->ipcccontents, 0, false};

    *len = 0;
    if (wandder_search_items(etsidec->dec, 0, &(etsidec->root), &ipcctgt, 1,
                &found, 1) == 0) {
        return NULL;
    }
    *len = found->list[0].item->length;
    vp = found->list[0].item->valptr;

    wandder_free_found(found);
    return vp;
}

char *wandder_etsili_get_liid(wandder_etsispec_t *etsidec, char *space,
        int spacelen) {

    char *liidptr;

    wandder_found_t *found = NULL;
    wandder_target_t liidtgt = {&(etsidec->psheader), 1, false};

    if (etsidec->decstate == 0) {
        fprintf(stderr, "No buffer attached to this decoder -- please call"
                "wandder_attach_etsili_buffer() first!\n");
        return NULL;
    }

    wandder_reset_decoder(etsidec->dec);
    if (wandder_search_items(etsidec->dec, 0, &(etsidec->root), &liidtgt, 1,
            &found, 1) == 0) {
        return NULL;
    }

    return wandder_get_valuestr(found->list[0].item, space, (uint16_t)spacelen,
            WANDDER_TAG_OCTETSTRING);
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

    if (name != NULL) {
        snprintf(valstr, len, "%s", name);
        return name;
    }

    return NULL;
}

static void free_dumpers(wandder_etsispec_t *dec) {
    free(dec->ipvalue.members);
    free(dec->ipaddress.members);
    free(dec->ipcccontents.members);
    free(dec->ipcc.members);
    free(dec->netelid.members);
    free(dec->netid.members);
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
                .interpretas = WANDDER_TAG_OCTETSTRING
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
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->ipaddress.sequence = WANDDER_NOACTION;

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

    dec->netid.membercount = 3;
    ALLOC_MEMBERS(dec->netid);
    dec->netid.members[0] =
        (struct wandder_dump_action) {
                .name = "operatorIdentifier",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->netid.members[1] =
        (struct wandder_dump_action) {
                .name = "networkElementIdentifier",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    dec->netid.members[2] =
        (struct wandder_dump_action) {
                .name = "eTSI671NEID",
                .descend = &dec->netelid,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->netid.sequence = WANDDER_NOACTION;

    dec->cid.membercount = 3;
    ALLOC_MEMBERS(dec->cid);
    dec->cid.members[0] =
        (struct wandder_dump_action) {
                .name = "networkIdentifier",
                .descend = &dec->netid,
                .interpretas = WANDDER_TAG_NULL
        };
    dec->cid.members[1] =
        (struct wandder_dump_action) {
                .name = "communicationIdentifier",
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
    dec->cccontents.members[4] = WANDDER_NOACTION;
    dec->cccontents.members[5] = WANDDER_NOACTION;
    dec->cccontents.members[6] = WANDDER_NOACTION;
    dec->cccontents.members[7] = WANDDER_NOACTION;
    dec->cccontents.members[8] = WANDDER_NOACTION;
    dec->cccontents.members[9] = WANDDER_NOACTION;
    dec->cccontents.members[10] = WANDDER_NOACTION;
    dec->cccontents.members[11] = WANDDER_NOACTION;
    dec->cccontents.members[12] = WANDDER_NOACTION;
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
    dec->iricontents.members[4] = WANDDER_NOACTION;
    dec->iricontents.members[5] = WANDDER_NOACTION;
    dec->iricontents.members[6] = WANDDER_NOACTION;
    dec->iricontents.members[7] = WANDDER_NOACTION;
    dec->iricontents.members[8] = WANDDER_NOACTION;
    dec->iricontents.members[9] = WANDDER_NOACTION;
    dec->iricontents.members[10] = WANDDER_NOACTION;
    dec->iricontents.members[11] =   // TODO
        (struct wandder_dump_action) {
                .name = "iPMMIRI",
                .descend = NULL,
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
                .descend = NULL,
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




// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
