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

wandder_dumper_t *wandder_get_etsili_structure(void);

struct timeval wandder_etsili_get_header_timestamp(wandder_decoder_t *dec);
uint32_t wandder_etsili_get_pdu_length(wandder_decoder_t *dec);
char *wandder_etsili_get_next_fieldstr(wandder_decoder_t *dec, char *space,
        int spacelen, wandder_etsi_stack_t **stack);
uint8_t *wandder_etsili_get_cc_contents(wandder_decoder_t *dec, uint32_t *len);

void wandder_etsili_free_stack(wandder_etsi_stack_t *stack);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
