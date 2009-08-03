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

#include "client.h"
#include "domain.h"
#include "log.h"

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>

/** free memory used by a client, including sockets and the client
    struct itself */
static void free_client(struct client *client) {
    unsigned z;

    assert(client != NULL);
    assert(client->domain == NULL);
    assert(client->prev == NULL);
    assert(client->next == NULL);

    for (z = 0; z < client->num_sockets; z++)
        close(client->sockets[z]);

    if (client->font_buffer != NULL)
        free(client->font_buffer);

    for (z = 0; z < client->num_chats; z++) {
        free(client->chats[z]);
    }

    free(client);
}

#ifndef DISABLE_LOGGING
void
update_client_name(struct client *client)
{
    struct sockaddr_in *addr_in = (struct sockaddr_in*)&client->address;
    char ip[16];

    inet_ntop(addr_in->sin_family, &addr_in->sin_addr,
              ip, sizeof(ip));

    if (client->have_position) {
        snprintf(client->name, sizeof(client->name),
                 "%s('%s';%u.%u.%u.%u)", ip,
                 client->info.noip.name,
                 client->info.ip[0], client->info.ip[1],
                 client->info.ip[2], client->info.ip[3]);
    } else {
        snprintf(client->name, sizeof(client->name),
                 "%s:%u", ip, addr_in->sin_port);
    }
}
#endif /* DISABLE_LOGGING */

struct client *
create_client(struct domain *domain, int sockfd,
#ifndef DISABLE_LOGGING
              struct sockaddr *addr, socklen_t addrlen,
#endif
              int randomfd)
{
    struct client *client;
    int ret;
#ifdef HAVE_DEV_RANDOM
    ssize_t nbytes;
#endif

    client = calloc(1, sizeof(*client));
    if (client == NULL)
        return NULL;

#ifndef DISABLE_LOGGING
    if ((size_t)addrlen > sizeof(client->address))
        addrlen = sizeof(client->address);
    memcpy(&client->address, addr, addrlen);
#endif /* DISABLE_LOGGING */

    /* a good random client id is vitally important for security,
       because secondary connections authorized themselves with it */
#ifdef HAVE_DEV_RANDOM
    nbytes = read(randomfd, &client->id, sizeof(client->id));
    if (nbytes < (ssize_t)sizeof(client->id)) {
        fprintf(stderr, "random number generation failed\n");
        free(client);
        return NULL;
    }
#else
    (void)randomfd;

    client->id = (random() << 24) + (random() << 16)
        + (random() << 8) + random();
#endif

    client->sockets[0] = sockfd;
    client->num_sockets = 1;
    client->timeout = time(NULL) + 60;

#ifndef DISABLE_LOGGING
    update_client_name(client);
#endif

    ret = add_client(domain, client);
    if (!ret) {
        log(1, "domain 0 is full, rejecting new client %s\n",
            client->name);
        free_client(client);
        return NULL;
    }

    log(2, "new client: %s\n", client->name);

    return client;
}

int
move_client(struct client *client, struct domain *domain)
{
    int ret;
    struct domain *old_domain = client->domain;

    assert(client != NULL);
    assert(client->domain != NULL);
    assert(domain != NULL);
    assert(client->domain->host == domain->host);

    if (client->domain == domain)
        return 1;

    remove_client(client);
    ret = add_client(domain, client);
    if (!ret) {
        log(1, "domain '%s' is full\n", domain->password);
        add_client(old_domain, client);
        return 0;
    }

    return 1;
}

int
append_client(struct client *dest, struct client *src, unsigned *socket_index)
{
    assert(dest->num_sockets > 0);
    assert(src->num_sockets > 0);
    assert(*socket_index < src->num_sockets);

    if (src->num_sockets + dest->num_sockets > MAX_SOCKETS)
        return -1;

    if (socket_index != NULL)
        *socket_index += dest->num_sockets;

    memcpy(dest->sockets + dest->num_sockets, src->sockets,
           src->num_sockets * sizeof(dest->sockets[0]));
    dest->num_sockets += src->num_sockets;
    src->num_sockets = 0;
    src->should_destroy = 1;

    return 0;
}

void
kill_client(struct client *client)
{
    log(2, "kill_client %s\n", client->name);

    remove_client(client);
    free_client(client);
}
