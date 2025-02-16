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
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include "itemhandler.h"


static inline wandder_itemblob_t *create_fresh_blob(uint32_t itemcount,
        size_t itemsize, wandder_itemhandler_t *handler) {


    wandder_itemblob_t *blob;
    size_t upsize;

    upsize = (((itemsize * itemcount) / handler->pagesize) + 1) *
            handler->pagesize;
    blob = (wandder_itemblob_t *)malloc(sizeof(wandder_itemblob_t));
    blob->blob = mmap(NULL, upsize, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (blob->blob == MAP_FAILED) {
        fprintf(stderr, "mmap failed: %s\n", strerror(errno));
        free(blob);
        return NULL;
    }

    blob->blobsize = upsize;
    blob->itemsize = itemsize;
    blob->alloceditems = itemcount;
    blob->nextavail = 0;
    blob->released = 0;
    blob->nextfree = NULL;
    return blob;
}

wandder_itemhandler_t *init_wandder_itemhandler(size_t itemsize,
        uint32_t itemsperalloc) {

    wandder_itemhandler_t *handler;

    handler = (wandder_itemhandler_t *)malloc(sizeof(wandder_itemhandler_t));

    if (!handler) {
        return NULL;
    }
    handler->items_per_blob = itemsperalloc;
    handler->itemsize = itemsize;
    handler->freelistavail = 0;
    handler->pagesize = sysconf(_SC_PAGE_SIZE);
    handler->current = create_fresh_blob(itemsperalloc, itemsize, handler);
    handler->freelist = NULL;
    handler->unreleased = 1;

    return handler;
}

void destroy_wandder_itemhandler(wandder_itemhandler_t *handler) {
    wandder_itemblob_t *blob, *tmp;

    blob = handler->freelist;
    while (blob) {
        tmp = blob;
        blob = blob->nextfree;
        munmap(tmp->blob, tmp->blobsize);
        free(tmp);
    }

    if (handler->current->released >= handler->current->nextavail) {
        munmap(handler->current->blob, handler->current->blobsize);
        free(handler->current);
    }

    free(handler);
}

uint8_t *get_wandder_handled_item(wandder_itemhandler_t *handler,
        wandder_itemblob_t **itemsource) {

    uint8_t *mem;

    if (handler->current->nextavail >= handler->current->alloceditems) {
        /* No slots left in the current blob */
        if (handler->current->released == handler->current->alloceditems) {
            /* User is releasing as fast as they are allocating, so we
             * can re-use current. */
            handler->current->nextavail = 0;
            handler->current->released = 0;
            handler->current->nextfree = NULL;
        }
        else if (handler->freelist == NULL) {
            handler->current = create_fresh_blob(handler->items_per_blob,
                    handler->itemsize, handler);
            handler->unreleased ++;
        } else {
            /* Use the first blob on our freelist */
            handler->current = handler->freelist;
            handler->freelist = handler->freelist->nextfree;
            handler->current->nextavail = 0;
            handler->current->released = 0;
            handler->current->nextfree = NULL;
            handler->freelistavail --;
            handler->unreleased ++;
        }
    }

    mem = handler->current->blob + (handler->current->nextavail *
            handler->current->itemsize);
    handler->current->nextavail ++;
    *itemsource = handler->current;
    return mem;
}


void release_wandder_handled_item(wandder_itemhandler_t *handler,
        wandder_itemblob_t *itemsource) {

    itemsource->released ++;

    if (itemsource->released > handler->items_per_blob) {
        return;
    }

    if (itemsource != handler->current &&
            itemsource->released == handler->items_per_blob) {
        assert(handler->freelist != itemsource);
        itemsource->nextfree = handler->freelist;
        handler->freelist = itemsource;
        handler->freelistavail ++;
        handler->unreleased --;
    }

    while (handler->freelistavail > 20) {
        wandder_itemblob_t *tmp = handler->freelist;
        handler->freelist = handler->freelist->nextfree;
        handler->freelistavail --;
        munmap(tmp->blob, tmp->blobsize);
        free(tmp);
    }
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
