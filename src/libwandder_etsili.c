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
wandder_dumper_t payload;
wandder_dumper_t psheader;
wandder_dumper_t pspdu;
wandder_dumper_t ipcc;
wandder_dumper_t ipcccontents;
wandder_dumper_t iripayloadseq;

static int init_called = 0;

static void init_dumpers(void);
static char *interpret_enum(wandder_item_t *item, wandder_dumper_t *curr,
        char *valstr, int len);

wandder_dumper_t *wandder_get_etsili_structure(void) {
    if (!init_called) {
        init_dumpers();
        init_called = 1;
    }

    return &root;
}

struct timeval wandder_etsili_get_header_timestamp(wandder_decoder_t *dec) {
    struct timeval tv;
    uint16_t savedlevel = 0;

    if (!init_called) {
        init_dumpers();
        init_called = 1;
    }


    /* Find PSHeader */
    wandder_reset_decoder(dec);
    wandder_found_t *found = NULL;
    wandder_target_t pshdrtgt = {&pspdu, 1, false};

    tv.tv_sec = 0;
    tv.tv_usec = 0;

    if (wandder_search_items(dec, 0, &root, &pshdrtgt, 1, &found, 1) == 0) {
        return tv;
    }

    /* dec->current should be pointing right at PSHeader */
    savedlevel = wandder_get_level(dec);

    wandder_decode_next(dec);
    while (wandder_get_level(dec) > savedlevel) {
        if (wandder_get_identifier(dec) == 5) {
            tv = wandder_generalizedts_to_timeval(wandder_get_itemptr(dec),
                    wandder_get_itemlen(dec));
            break;
        }
        if (wandder_get_identifier(dec) == 7) {
            printf("got msts field, please write a parser for it!\n");

            /* TODO parse msts field */
            break;
        }
        wandder_decode_next(dec);
    }
    wandder_free_found(found);
    return tv;

}

uint32_t wandder_etsili_get_pdu_length(wandder_decoder_t *dec) {

    /* Easy, reset the decoder then grab the length of the first element */
    wandder_reset_decoder(dec);

    if (wandder_decode_next(dec) <= 0) {
        return 0;
    }

    /* Don't forget to include the preamble length so the caller can skip
     * over the entire PDU if desired.
     */
    return wandder_get_itemlen(dec) + dec->current->preamblelen;
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

char *wandder_etsili_get_next_fieldstr(wandder_decoder_t *dec, char *space,
        int spacelen, wandder_etsi_stack_t **stack) {
    uint32_t ident;
    wandder_dumper_t *curr = NULL;
    char valstr[2048];

    if (!init_called) {
        init_dumpers();
        init_called = 1;
    }

    if (*stack == NULL) {
        *stack = (wandder_etsi_stack_t *)malloc(sizeof(wandder_etsi_stack_t));
        (*stack)->stk = (wandder_dumper_t **)malloc(sizeof(wandder_dumper_t *) * 10);
        (*stack)->atthislevel = (int *)malloc(sizeof(int *) * 10);

        (*stack)->alloced = 10;
        (*stack)->stk[0] = &root;
        (*stack)->current = 0;
        (*stack)->atthislevel[0] = 0;
    }

    if (wandder_decode_next(dec) <= 0) {
        return NULL;
    }


    while (wandder_get_level(dec) < (*stack)->current) {
        assert((*stack)->current > 0);
        (*stack)->current --;
    }

    curr = (*stack)->stk[(*stack)->current];

    switch(wandder_get_class(dec)) {

        case WANDDER_CLASS_CONTEXT_PRIMITIVE:
            ident = wandder_get_identifier(dec);
            ((*stack)->atthislevel[(*stack)->current])++;

            if (curr->members[ident].interpretas == WANDDER_TAG_IPPACKET) {
                /* Reached the actual IP contents  -- stop */
                return NULL;
            }

            if (curr->members[ident].interpretas == WANDDER_TAG_ENUM) {
                if (interpret_enum(dec->current, curr, valstr, 2048) == NULL) {
                    fprintf(stderr, "Failed to interpret field %d:%d\n",
                            (*stack)->current, ident);
                    return NULL;
                }
            } else {
                if (!wandder_get_valuestr(dec->current, valstr, 2048,
                        curr->members[ident].interpretas)) {
                    fprintf(stderr, "Failed to interpret field %d:%d\n",
                            (*stack)->current, ident);
                    return NULL;
                }
            }

            snprintf(space, spacelen, "%s: %s", curr->members[ident].name, valstr);
            break;

        case WANDDER_CLASS_UNIVERSAL_PRIMITIVE:
            ident = (uint32_t)(*stack)->atthislevel[(*stack)->current];
            ((*stack)->atthislevel[(*stack)->current])++;
            if (!wandder_get_valuestr(dec->current, valstr, 2048,
                    wandder_get_identifier(dec))) {
                fprintf(stderr, "Failed to interpret standard field %d:%d\n",
                        (*stack)->current, ident);
                return NULL;
            }
            snprintf(space, spacelen, "%s: %s", curr->members[ident].name, valstr);
            break;

        case WANDDER_CLASS_UNIVERSAL_CONSTRUCT:
            if (curr == NULL) {
                return NULL;
            }
            snprintf(space, spacelen, "%s:", curr->sequence.name);
            ((*stack)->atthislevel[(*stack)->current])++;
            push_stack(*stack, curr->sequence.descend);
            break;

        case WANDDER_CLASS_CONTEXT_CONSTRUCT:
            if (curr == NULL) {
                return NULL;
            }
            ident = wandder_get_identifier(dec);
            ((*stack)->atthislevel[(*stack)->current])++;
            snprintf(space, spacelen, "%s:", curr->members[ident].name);
            push_stack(*stack, curr->members[ident].descend);
            break;
        default:
            return NULL;
    }

    
    return space;
}

uint8_t *wandder_etsili_get_cc_contents(wandder_decoder_t *dec, uint32_t *len) {
    uint8_t *vp = NULL;
    if (!init_called) {
        init_dumpers();
        init_called = 1;
    }
    /* Find IPCCContents */
    wandder_reset_decoder(dec);
    wandder_found_t *found = NULL;
    wandder_target_t ipcctgt = {&ipcccontents, 0, false};

    *len = 0;
    if (wandder_search_items(dec, 0, &root, &ipcctgt, 1, &found, 1) == 0) {
        return NULL;
    }
    *len = found->list[0].item->length;
    vp = found->list[0].item->valptr;

    wandder_free_found(found);
    return vp;
}

void wandder_etsili_free_stack(wandder_etsi_stack_t *stack) {
    free(stack->stk);
    free(stack->atthislevel);
    free(stack);
}




/* These functions are hideous, but act as a C-compatible version of the
 * ASN.1 specification of the ETSI LI standard.
 *
 * Try not to look too closely at this stuff unless you really need to.
 */


static char *interpret_enum(wandder_item_t *item, wandder_dumper_t *curr,
        char *valstr, int len) {

    uint32_t intlen = 0;
    int64_t enumval = 0;
    char *name = NULL;

    /* First, decode the valptr as though it were an integer */
    enumval = wandder_get_integer_value(item, &intlen);

    if (intlen == 0) {
        fprintf(stderr, "Failed to interpret enum value as an integer.\n");
        return NULL;
    }

    if (item->identifier == 1 && curr == &ipaddress) {
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

    if (item->identifier == 3 && curr == &ipaddress) {
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

    if (item->identifier == 0 && curr == &ccpayload) {
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

    if ((item->identifier == 4 && curr == &ccpayload) ||
            (item->identifier == 4 && curr == &iripayload) ||
            (item->identifier == 8 && curr == &psheader)) {
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

    if (item->identifier == 0 && curr == &ipiricontents) {
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

    if (item->identifier == 2 && curr == &ipiricontents) {
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

    if (item->identifier == 3 && curr == &ipiricontents) {
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

    if (item->identifier == 12 && curr == &ipiricontents) {
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

    if (item->identifier == 22 && curr == &ipiricontents) {
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

    if (item->identifier == 0 && curr == &iripayload) {
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

    if (name != NULL) {
        snprintf(valstr, len, "%s", name);
        return name;
    }

    return NULL;
}

static void init_dumpers(void) {

    ipvalue.membercount = 3;
    ALLOC_MEMBERS(ipvalue);
    ipvalue.members[0] = WANDDER_NOACTION;
    ipvalue.members[1] =
        (struct wandder_dump_action) {
                .name = "iPBinaryAddress",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    ipvalue.members[2] =
        (struct wandder_dump_action) {
                .name = "iPTextAddress",
                .descend = NULL,
                .interpretas = WANDDER_TAG_IA5
        };

    ipaddress.membercount = 6;
    ALLOC_MEMBERS(ipaddress);
    ipaddress.members[0] = WANDDER_NOACTION;
    ipaddress.members[1] =
        (struct wandder_dump_action) {
                .name = "iP-type",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    ipaddress.members[2] =
        (struct wandder_dump_action) {
                .name = "iP-value",
                .descend = &ipvalue,
                .interpretas = WANDDER_TAG_NULL
        };
    ipaddress.members[3] =
        (struct wandder_dump_action) {
                .name = "iP-assignment",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    ipaddress.members[4] =
        (struct wandder_dump_action) {
                .name = "iPv6PrefixLength",
                .descend = NULL,
                .interpretas = WANDDER_TAG_INTEGER
        };
    ipaddress.members[5] =
        (struct wandder_dump_action) {
                .name = "iPv4SubnetMask",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };

    ipcccontents.membercount = 1;
    ALLOC_MEMBERS(ipcccontents);
    ipcccontents.members[0] =
        (struct wandder_dump_action) {
                .name = "iPPackets",
                .descend = NULL,
                .interpretas = WANDDER_TAG_IPPACKET
        };

    ipcc.membercount = 2;
    ALLOC_MEMBERS(ipcc);

    ipcc.members[0] =
        (struct wandder_dump_action) {
                .name = "iPCCObjId",
                .descend = NULL,
                .interpretas = WANDDER_TAG_RELATIVEOID
        };
    ipcc.members[1] =
        (struct wandder_dump_action) {
                .name = "iPCCContents",
                .descend = &ipcccontents,
                .interpretas = WANDDER_TAG_NULL
        };

    netelid.membercount = 6;
    ALLOC_MEMBERS(netelid);

    netelid.members[0] = WANDDER_NOACTION;
    netelid.members[1] =
        (struct wandder_dump_action) {
                .name = "e164-Format",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    netelid.members[2] =
        (struct wandder_dump_action) {
                .name = "x25-Format",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    netelid.members[3] =
        (struct wandder_dump_action) {
                .name = "iP-Format",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    netelid.members[4] =
        (struct wandder_dump_action) {
                .name = "dNS-Format",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    netelid.members[5] =        // TODO
        (struct wandder_dump_action) {
                .name = "iP-Address",
                .descend = &ipaddress,
                .interpretas = WANDDER_TAG_NULL
        };
    netelid.sequence = WANDDER_NOACTION;

    root.membercount = 0;
    root.members = NULL;
    root.sequence =
        (struct wandder_dump_action) {
                .name = "pS-PDU",
                .descend = &pspdu,
                .interpretas = WANDDER_TAG_NULL
        };

    netid.membercount = 3;
    ALLOC_MEMBERS(netid);
    netid.members[0] =
        (struct wandder_dump_action) {
                .name = "operatorIdentifier",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    netid.members[1] =
        (struct wandder_dump_action) {
                .name = "networkElementIdentifier",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    netid.members[2] =
        (struct wandder_dump_action) {
                .name = "eTSI671NEID",
                .descend = &netelid,
                .interpretas = WANDDER_TAG_NULL
        };
    netid.sequence = WANDDER_NOACTION;

    cid.membercount = 3;
    ALLOC_MEMBERS(cid);
    cid.members[0] =
        (struct wandder_dump_action) {
                .name = "networkIdentifier",
                .descend = &netid,
                .interpretas = WANDDER_TAG_NULL
        };
    cid.members[1] =
        (struct wandder_dump_action) {
                .name = "communicationIdentifier",
                .descend = NULL,
                .interpretas = WANDDER_TAG_INTEGER
        };
    cid.members[2] =
        (struct wandder_dump_action) {
                .name = "deliveryCountryCode",
                .descend = NULL,
                .interpretas = WANDDER_TAG_PRINTABLE
        };
    cid.sequence = WANDDER_NOACTION;

    msts.membercount = 2;
    ALLOC_MEMBERS(msts);
    msts.members[0] =
        (struct wandder_dump_action) {
                .name = "seconds",
                .descend = NULL,
                .interpretas = WANDDER_TAG_INTEGER
        };
    msts.members[1] =
        (struct wandder_dump_action) {
                .name = "microSeconds",
                .descend = NULL,
                .interpretas = WANDDER_TAG_INTEGER
        };
    msts.sequence = WANDDER_NOACTION;

    cccontents.membercount = 19;
    ALLOC_MEMBERS(cccontents);
    cccontents.members[0] = WANDDER_NOACTION;
    cccontents.members[1] =     // TODO
        (struct wandder_dump_action) {
                .name = "emailCC",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
    cccontents.members[2] =
        (struct wandder_dump_action) {
                .name = "iPCC",
                .descend = &ipcc,
                .interpretas = WANDDER_TAG_NULL
        };
    cccontents.members[3] = WANDDER_NOACTION;
    cccontents.members[4] = WANDDER_NOACTION;
    cccontents.members[5] = WANDDER_NOACTION;
    cccontents.members[6] = WANDDER_NOACTION;
    cccontents.members[7] = WANDDER_NOACTION;
    cccontents.members[8] = WANDDER_NOACTION;
    cccontents.members[9] = WANDDER_NOACTION;
    cccontents.members[10] = WANDDER_NOACTION;
    cccontents.members[11] = WANDDER_NOACTION;
    cccontents.members[12] = WANDDER_NOACTION;
    cccontents.members[13] = WANDDER_NOACTION;
    cccontents.members[14] = WANDDER_NOACTION;
    cccontents.members[15] = WANDDER_NOACTION;
    cccontents.members[16] = WANDDER_NOACTION;
    cccontents.members[17] = WANDDER_NOACTION;
    cccontents.members[18] = WANDDER_NOACTION;

    ccpayload.membercount = 5;
    ALLOC_MEMBERS(ccpayload);
    ccpayload.members[0] =
        (struct wandder_dump_action) {
                .name = "payloadDirection",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    ccpayload.members[1] =
        (struct wandder_dump_action) {
                .name = "timeStamp",
                .descend = NULL,
                .interpretas = WANDDER_TAG_GENERALTIME
        };
    ccpayload.members[2] =
        (struct wandder_dump_action) {
                .name = "cCContents",
                .descend = &cccontents,
                .interpretas = WANDDER_TAG_NULL
        };
    ccpayload.members[3] =
        (struct wandder_dump_action) {
                .name = "microSecondTimestamp",
                .descend = &msts,
                .interpretas = WANDDER_TAG_NULL
        };
    ccpayload.members[4] =
        (struct wandder_dump_action) {
                .name = "timeStampQualifier",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    ccpayload.sequence = WANDDER_NOACTION;

    ccpayloadseq.membercount = 0;
    ccpayloadseq.members = NULL;
    ccpayloadseq.sequence =
        (struct wandder_dump_action) {
                .name = "CCPayload",
                .descend = &ccpayload,
                .interpretas = WANDDER_TAG_NULL
        };

    ipiriid.membercount = 3;
    ALLOC_MEMBERS(ipiriid);
    ipiriid.members[0] =
        (struct wandder_dump_action) {
                .name = "printableIDType",
                .descend = NULL,
                .interpretas = WANDDER_TAG_UTF8STR
        };
    ipiriid.members[1] =
        (struct wandder_dump_action) {
                .name = "macAddressType",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    ipiriid.members[2] =
        (struct wandder_dump_action) {
                .name = "ipAddressType",
                .descend = &ipaddress,
                .interpretas = WANDDER_TAG_NULL
        };

    ipiricontents.membercount = 24;
    ALLOC_MEMBERS(ipiricontents);
    ipiricontents.members[0] =
        (struct wandder_dump_action) {
                .name = "accessEventType",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    ipiricontents.members[1] =
        (struct wandder_dump_action) {
                .name = "targetUsername",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    ipiricontents.members[2] =
        (struct wandder_dump_action) {
                .name = "internetAccessType",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    ipiricontents.members[3] =
        (struct wandder_dump_action) {
                .name = "iPVersion",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    ipiricontents.members[4] =
        (struct wandder_dump_action) {
                .name = "targetIPAddress",
                .descend = &ipaddress,
                .interpretas = WANDDER_TAG_NULL
        };
    ipiricontents.members[5] =
        (struct wandder_dump_action) {
                .name = "targetNetworkID",
                .descend = NULL,
                .interpretas = WANDDER_TAG_UTF8STR
        };
    ipiricontents.members[6] =
        (struct wandder_dump_action) {
                .name = "targetCPEID",
                .descend = NULL,
                .interpretas = WANDDER_TAG_UTF8STR
        };
    ipiricontents.members[7] =
        (struct wandder_dump_action) {
                .name = "targetLocation",
                .descend = NULL,
                .interpretas = WANDDER_TAG_UTF8STR
        };
    ipiricontents.members[8] =
        (struct wandder_dump_action) {
                .name = "pOPPortNumber",
                .descend = NULL,
                .interpretas = WANDDER_TAG_INTEGER
        };
    ipiricontents.members[9] =
        (struct wandder_dump_action) {
                .name = "callBackNumber",
                .descend = NULL,
                .interpretas = WANDDER_TAG_UTF8STR
        };
    ipiricontents.members[10] =
        (struct wandder_dump_action) {
                .name = "startTime",
                .descend = NULL,
                .interpretas = WANDDER_TAG_GENERALTIME
        };
    ipiricontents.members[11] =
        (struct wandder_dump_action) {
                .name = "endTime",
                .descend = NULL,
                .interpretas = WANDDER_TAG_GENERALTIME
        };
    ipiricontents.members[12] =
        (struct wandder_dump_action) {
                .name = "endReason",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    ipiricontents.members[13] =
        (struct wandder_dump_action) {
                .name = "octetsReceived",
                .descend = NULL,
                .interpretas = WANDDER_TAG_INTEGER
        };
    ipiricontents.members[14] =
        (struct wandder_dump_action) {
                .name = "octetsTransmitted",
                .descend = NULL,
                .interpretas = WANDDER_TAG_INTEGER
        };
    ipiricontents.members[15] =
        (struct wandder_dump_action) {
                .name = "rawAAAData",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    ipiricontents.members[16] =
        (struct wandder_dump_action) {
                .name = "expectedEndTime",
                .descend = NULL,
                .interpretas = WANDDER_TAG_GENERALTIME
        };
    ipiricontents.members[17] =
        (struct wandder_dump_action) {
                .name = "pOPPhoneNumber",
                .descend = NULL,
                .interpretas = WANDDER_TAG_UTF8STR
        };
    ipiricontents.members[18] =
        (struct wandder_dump_action) {
                .name = "pOPIdentifier",
                .descend = &ipiriid,
                .interpretas = WANDDER_TAG_NULL
        };
    ipiricontents.members[19] =
        (struct wandder_dump_action) {
                .name = "pOPIPAddress",
                .descend = &ipaddress,
                .interpretas = WANDDER_TAG_NULL
        };
    ipiricontents.members[20] = WANDDER_NOACTION;   // TODO
    ipiricontents.members[21] =
        (struct wandder_dump_action) {
                .name = "additionalIPAddress",
                .descend = &ipaddress,
                .interpretas = WANDDER_TAG_NULL
        };
    ipiricontents.members[22] =
        (struct wandder_dump_action) {
                .name = "authenticationType",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    ipiricontents.members[23] = WANDDER_NOACTION;   // TODO

    ipiri.membercount = 2;
    ALLOC_MEMBERS(ipiri);
    ipiri.members[0] =
        (struct wandder_dump_action) {
                .name = "iPIRIObjId",
                .descend = NULL,
                .interpretas = WANDDER_TAG_RELATIVEOID
        };
    ipiri.members[1] =
        (struct wandder_dump_action) {
                .name = "iPIRIContents",
                .descend = &ipiricontents,
                .interpretas = WANDDER_TAG_NULL
        };

    iricontents.membercount = 16;
    ALLOC_MEMBERS(iricontents);
    iricontents.members[0] = WANDDER_NOACTION;
    iricontents.members[1] =     // TODO
        (struct wandder_dump_action) {
                .name = "emailIRI",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
    iricontents.members[2] =
        (struct wandder_dump_action) {
                .name = "iPIRI",
                .descend = &ipiri,
                .interpretas = WANDDER_TAG_NULL
        };
    iricontents.members[3] = WANDDER_NOACTION;
    iricontents.members[4] = WANDDER_NOACTION;
    iricontents.members[5] = WANDDER_NOACTION;
    iricontents.members[6] = WANDDER_NOACTION;
    iricontents.members[7] = WANDDER_NOACTION;
    iricontents.members[8] = WANDDER_NOACTION;
    iricontents.members[9] = WANDDER_NOACTION;
    iricontents.members[10] = WANDDER_NOACTION;
    iricontents.members[11] =   // TODO
        (struct wandder_dump_action) {
                .name = "iPMMIRI",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
    iricontents.members[12] = WANDDER_NOACTION;
    iricontents.members[13] = WANDDER_NOACTION;
    iricontents.members[14] = WANDDER_NOACTION;
    iricontents.members[15] = WANDDER_NOACTION;


    iripayload.membercount = 5;
    ALLOC_MEMBERS(iripayload);
    iripayload.members[0] =
        (struct wandder_dump_action) {
                .name = "iRIType",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };
    iripayload.members[1] =
        (struct wandder_dump_action) {
                .name = "timeStamp",
                .descend = NULL,
                .interpretas = WANDDER_TAG_GENERALTIME
        };
    iripayload.members[2] =
        (struct wandder_dump_action) {
                .name = "iRIContents",
                .descend = &iricontents,
                .interpretas = WANDDER_TAG_NULL
        };
    iripayload.members[3] =
        (struct wandder_dump_action) {
                .name = "microSecondTimestamp",
                .descend = &msts,
                .interpretas = WANDDER_TAG_NULL
        };
    iripayload.members[4] =
        (struct wandder_dump_action) {
                .name = "timeStampQualifier",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };

    iripayloadseq.membercount = 0;
    iripayloadseq.members = NULL;
    iripayloadseq.sequence =
        (struct wandder_dump_action) {
                .name = "IRIPayload",
                .descend = &iripayload,
                .interpretas = WANDDER_TAG_NULL
        };

    payload.membercount = 5;
    ALLOC_MEMBERS(payload);
    payload.sequence = WANDDER_NOACTION;
    payload.members[0] =        // TODO
        (struct wandder_dump_action) {
                .name = "iRIPayloadSequence",
                .descend = &iripayloadseq,
                .interpretas = WANDDER_TAG_NULL
        };
    payload.members[1] =
        (struct wandder_dump_action) {
                .name = "cCPayloadSequence",
                .descend = &ccpayloadseq,
                .interpretas = WANDDER_TAG_NULL
        };
    payload.members[2] =        // Not required
        (struct wandder_dump_action) {
                .name = "tRIPayload",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
    payload.members[3] =        // Not required
        (struct wandder_dump_action) {
                .name = "hI1-Operation",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };
    payload.members[4] =        // TODO?
        (struct wandder_dump_action) {
                .name = "encryptionContainer",
                .descend = NULL,
                .interpretas = WANDDER_TAG_NULL
        };

    psheader.membercount = 9;
    ALLOC_MEMBERS(psheader);
    psheader.sequence = WANDDER_NOACTION;
    psheader.members[0] =
        (struct wandder_dump_action) {
                .name = "li-psDomainId",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OID
        };
    psheader.members[1] =
        (struct wandder_dump_action) {
                .name = "lawfulInterceptionIdentifier",
                .descend = NULL,
                .interpretas = WANDDER_TAG_OCTETSTRING
        };
    psheader.members[2] =
        (struct wandder_dump_action) {
                .name = "authorizationCountryCode",
                .descend = NULL,
                .interpretas = WANDDER_TAG_PRINTABLE
        };
    psheader.members[3] =
        (struct wandder_dump_action) {
                .name = "communicationIdentifier",
                .descend = &cid,
                .interpretas = WANDDER_TAG_NULL
        };
    psheader.members[4] =
        (struct wandder_dump_action) {
                .name = "sequenceNumber",
                .descend = NULL,
                .interpretas = WANDDER_TAG_INTEGER
        };
    psheader.members[5] =
        (struct wandder_dump_action) {
                .name = "timeStamp",
                .descend = NULL,
                .interpretas = WANDDER_TAG_GENERALTIME
        };
    psheader.members[6] =
        (struct wandder_dump_action) {
                .name = "interceptionPointID",
                .descend = NULL,
                .interpretas = WANDDER_TAG_PRINTABLE
        };
    psheader.members[7] =
        (struct wandder_dump_action) {
                .name = "microSecondTimeStamp",
                .descend = &msts,
                .interpretas = WANDDER_TAG_NULL
        };
    psheader.members[8] =
        (struct wandder_dump_action) {
                .name = "timeStampQualifier",
                .descend = NULL,
                .interpretas = WANDDER_TAG_ENUM
        };


    pspdu.membercount = 3;
    ALLOC_MEMBERS(pspdu);
    pspdu.sequence = WANDDER_NOACTION;
    pspdu.members[0] = WANDDER_NOACTION;
    pspdu.members[1] =
        (struct wandder_dump_action) {
                .name = "PSHeader",
                .descend = &psheader,
                .interpretas = WANDDER_TAG_NULL
        };
    pspdu.members[2] =
        (struct wandder_dump_action) {
                .name = "Payload",
                .descend = &payload,
                .interpretas = WANDDER_TAG_NULL
        };
}




// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
