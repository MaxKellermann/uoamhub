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

#ifndef __UOAMHUB_DOMAIN_H
#define __UOAMHUB_DOMAIN_H

#include "list.h"

#include <stdint.h>

struct host;
struct client;

/** a domain - all clients who chose the same password are in the same
    domain and can see each others */
struct domain {
    struct list_head siblings;

    /** password of this domain */
    char password[20];
    /** the host this domain belongs to */
    struct host *host;

    /** pointer to the first client */
    struct list_head clients;

    /** number of clients */
    unsigned num_clients;
};

/** create a domain and add it to the host */
struct domain *
create_domain(struct host *host, const char *password);

/** kill a domain and remove it from the host */
void
kill_domain(struct domain *domain);

struct client *
domain_get_client(struct domain *domain, uint32_t id);

/** add an unbound client to a domain; fails if the domain is full */
int
add_client(struct domain *domain, struct client *client);

/** remove a bound client from its damain */
void
remove_client(struct client *client);

#endif
