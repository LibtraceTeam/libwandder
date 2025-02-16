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

#ifndef LIBWANDDER_ETSILI_BER_H_
#define LIBWANDDER_ETSILI_BER_H_

#include <libwandder.h>
#include <stdint.h>
#include <uthash.h>
#include "libwandder_etsili.h"

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
