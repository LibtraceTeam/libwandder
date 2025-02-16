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
#include "libwandder_etsili_ber.h"

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
            (uint8_t *)wandder_etsi_ipmmirioid, 
            sizeof wandder_etsi_ipmmirioid);

    pendarray[WANDDER_PREENCODE_IPCCOID] =  wandder_encode_new_ber( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_RELATIVEOID,
            (uint8_t *)wandder_etsi_ipccoid, 
            sizeof wandder_etsi_ipccoid);

    pendarray[WANDDER_PREENCODE_IPIRIOID] =  wandder_encode_new_ber( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_RELATIVEOID,
            (uint8_t *)wandder_etsi_ipirioid, 
            sizeof wandder_etsi_ipirioid);

    pendarray[WANDDER_PREENCODE_UMTSIRIOID] =  wandder_encode_new_ber( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_OID,
            (uint8_t *)wandder_etsi_umtsirioid, 
            sizeof wandder_etsi_umtsirioid);

    pendarray[WANDDER_PREENCODE_IPMMCCOID] =  wandder_encode_new_ber( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_RELATIVEOID,
            (uint8_t *)wandder_etsi_ipmmccoid, 
            sizeof wandder_etsi_ipmmccoid);

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
