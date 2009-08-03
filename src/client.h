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

#ifndef __UOAMHUB_CLIENT_H
#define __UOAMHUB_CLIENT_H

#include "protocol.h"
#include "config.h"
#include "list.h"

#include <stdint.h>
#include <sys/socket.h>

struct host;
struct domain;

/** a client, which may consist of more than one socket */
struct client {
    struct list_head siblings;

#ifndef DISABLE_LOGGING
    /** socket address */
    struct sockaddr address;
    /** length of address */
    socklen_t address_length;
    /** visible name */
    char name[64];
#endif
    /** client id */
    uint32_t id;
    /** list of all sockets (a client can use several sockets at
        once) */
    int sockets[MAX_SOCKETS];
    /** number of sockets in the sockets array */
    unsigned num_sockets;
    /** unix time when this client times out, unless he successfully
        talks to server meanwhile */
    time_t timeout;
    /** the domain this client is logged in */
    struct domain *domain;
    /** several flags */
    unsigned int should_destroy:1, handshake:1, authorized:1, have_position:1;
    /** player info, including name and position */
    struct player_info info;
    /** chat settings */
    void *font_buffer;
    /** size of the chat settings */
    size_t font_buffer_size;
    /** pending chat entries */
    struct chat *chats[MAX_CHATS];
    /** number of chat entries not yet sent to the client */
    unsigned num_chats;
};

#ifndef DISABLE_LOGGING
/** generate a new client->name from the client IP address and nick
    name */
void
update_client_name(struct client *client);
#endif

/** create a new client and adds it to the domain */
struct client *
create_client(struct domain *domain, int sockfd,
#ifndef DISABLE_LOGGING
              struct sockaddr *addr, socklen_t addrlen,
#endif
              int randomfd);

/** move a bound client to another domain */
int
move_client(struct client *client, struct domain *domain);

/** merge two clients */
int
append_client(struct client *dest, struct client *src, unsigned *socket_index);

/** kill a client */
void
kill_client(struct client *client);

#endif
