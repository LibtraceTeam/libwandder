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

#ifndef LIBWANDDER_ETSILI_H_
#define LIBWANDDER_ETSILI_H_

#include <libwandder.h>

typedef struct wandder_etsistack {

    int alloced;
    int current;
    wandder_dumper_t **stk;
    int *atthislevel;
} wandder_etsi_stack_t;

typedef struct wandder_etsispec {
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

    wandder_decoder_t *dec;
    wandder_etsi_stack_t *stack;

    uint8_t decstate;
} wandder_etsispec_t;

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
uint8_t *wandder_etsili_get_cc_contents(wandder_etsispec_t *dec, uint32_t *len);
char *wandder_etsili_get_liid(wandder_etsispec_t *dec, char *space,
        int spacelen);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
