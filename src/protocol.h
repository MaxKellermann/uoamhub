/*
 * uoamhub
 *
 * (c) 2004-2007 Max Kellermann <max@duempel.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef __UOAMHUB_PROTOCOL_H
#define __UOAMHUB_PROTOCOL_H

struct noip_player_info {
    char name[64];
    unsigned char reserved[12];
    unsigned char position[16];
};

/** this structure is sent by the client in position update packets */
struct player_info {
    /** the internal client's IP address, not affected by NAT */
    unsigned char ip[4];
    /** public client info */
    struct noip_player_info noip;
};

#endif
