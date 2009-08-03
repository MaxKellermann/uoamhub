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

#ifndef __UOAMHUB_CONFIG_H
#define __UOAMHUB_CONFIG_H

#include <sys/types.h>
#include <netdb.h>

/** source for client ids (which are important for security). if you
    have a hardware random device, change this */
#ifndef RANDOM_DEVICE
#define RANDOM_DEVICE "/dev/urandom"
#endif

/*
  feel free to tune:
*/

/** maximum number of domains */
#define MAX_DOMAINS 64

/** maximum number of clients per domain */
#define MAX_CLIENTS 256

/** maximum number of connections per client */
#define MAX_SOCKETS 16

/** length of the chat queue per client */
#define MAX_CHATS 64


/** global host configuration */
struct config {
    unsigned port;
    struct addrinfo *bind_address;
    char *password;
#ifndef DISABLE_DAEMON_CODE
    int no_daemon;
    const char *pidfile, *logger, *chroot_dir;
    uid_t uid;
    gid_t gid;
#endif /* DISABLE_DAEMON_CODE */
};


/** read configuration options from the command line */
void
parse_cmdline(struct config *config, int argc, char **argv);

/** free data in a config struct; the struct itself is not freed */
void
free_config(struct config *config);

#endif
