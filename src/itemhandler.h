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

#ifndef LIBWANDDER_ITEMHANDLER_H
#define LIBWANDDER_ITEMHANDLER_H

#include <inttypes.h>
#include <stdint.h>

#include "src/libwandder.h"

wandder_itemhandler_t *init_wandder_itemhandler(size_t itemsize,
        uint32_t itemsperalloc);
void destroy_wandder_itemhandler(wandder_itemhandler_t *hander);
uint8_t *get_wandder_handled_item(wandder_itemhandler_t *handler,
        wandder_itemblob_t **itemsource);
void release_wandder_handled_item(wandder_itemhandler_t *handler,
        wandder_itemblob_t *itemsource);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
