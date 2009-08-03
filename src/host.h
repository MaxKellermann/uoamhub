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

#ifndef __UOAMHUB_HOST_H
#define __UOAMHUB_HOST_H

#include "list.h"

#include <stdint.h>

struct domain;

/** a host - currently only one host is supported, so this is a
    singleton */
struct host {
    /** configuration of this host */
    const struct config *config;

    /** pointer to the first domain */
    struct list_head domains;

    /** number of domains */
    unsigned num_domains;
};

int
host_domains_full(struct host *host);

void
host_add_domain(struct host *host, struct domain *domain);

void
host_remove_domain(struct host *host, struct domain *domain);

/** find a client with the specified id on the whole host (all
    domains) */
struct client *
get_client(struct host *host, uint32_t id);

/** find a domain by its password */
struct domain *
get_domain(struct host *host, const char *password);

#endif
