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

#include "host.h"
#include "domain.h"
#include "client.h"
#include "config.h"

#include <assert.h>
#include <string.h>

int
host_domains_full(struct host *host)
{
    return host->num_domains >= MAX_DOMAINS;
}

void
host_add_domain(struct host *host, struct domain *domain)
{
    assert(host != NULL);
    assert(domain != NULL);
    assert(domain->host == NULL);

    domain->host = host;

    list_add(&domain->siblings, &host->domains);

    host->num_domains++;
}

void
host_remove_domain(struct host *host, struct domain *domain)
{
    assert(host != NULL);
    assert(domain != NULL);
    assert(domain->host == host);
    assert(host->num_domains > 0);

    domain->host = NULL;

    host->num_domains--;

    list_remove(&domain->siblings);
}

struct client *
get_client(struct host *host, uint32_t id)
{
    struct domain *domain;
    struct client *client;

    for (domain = (struct domain*)host->domains.next;
         domain != (struct domain*)&host->domains;
         domain = (struct domain*)domain->siblings.next) {
        assert(domain->host == host);

        client = domain_get_client(domain, id);
        if (client != NULL)
            return client;
    }

    return NULL;
}

struct domain *
get_domain(struct host *host, const char *password)
{
    struct domain *domain;

    for (domain = (struct domain*)host->domains.next;
         domain != (struct domain*)&host->domains;
         domain = (struct domain*)domain->siblings.next) {
        assert(domain->host == host);

        if (strcmp(password, domain->password) == 0)
            return domain;
    }

    return NULL;
}
