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

#include "config.h"
#include "version.h"
#include "log.h"

#include <sys/stat.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>

#ifdef __GLIBC__
#include <getopt.h>
#endif

/** print a short usage description */
static void
usage(void) __attribute__ ((noreturn));
static void
usage(void)
{
    fprintf(stderr, "usage: uoamhub [options]\n\n"
            "valid options:\n"
            " -h             help (this text)\n"
            " -V             print version number\n"
#ifdef __GLIBC__
            " --verbose\n"
#endif
            " -v             increase verbosity (default 1)\n"
#ifdef __GLIBC__
            " --quiet\n"
#endif
            " -q             reset verbosity to 0\n"
#ifdef __GLIBC__
            " --password file\n"
#endif
            " -w file        single-domain, only accept the password from the file\n"
#ifdef __GLIBC__
            " --port port\n"
#endif
            " -p port        listen on this port (default 2000)\n"
#ifdef __GLIBC__
            " --logger program\n"
#endif
            " -l program     specifies a logger program (executed by /bin/sh)\n"
#ifdef __GLIBC__
            " --chroot dir\n"
#endif
            " -r dir         chroot into this directory (requires root)\n"
#ifdef __GLIBC__
            " --user username\n"
#endif
            " -u username    change user id (don't run uoamhub as root!)\n"
            " -D             don't detach (daemonize)\n"
#ifdef __GLIBC__
            " --pidfile file\n"
#endif
            " -P file        create a pid file\n"
            "\n"
            );
    exit(1);
}

/** read the contents of a file into a new string on the heap */
static int
read_file_string(const char *filename, char **value)
{
    FILE *file;
    char line[1024], *p;
    int save_errno;
    size_t len;

    assert(value != NULL);
    assert(*value == NULL);

    /* open file */
    file = fopen(filename, "r");
    if (file == NULL)
        return -1;

    /* read the first line */
    p = fgets(line, sizeof(line), file);
    save_errno = errno;
    fclose(file);
    if (p == NULL) {
        errno = save_errno;
        return -1;
    }

    /* trim value */
    while (*p > 0 && *p <= 0x20)
        p++;

    len = strlen(p);

    while (p[len - 1] > 0 && p[len - 1] <= 0x20)
        len--;

    p[len] = 0;

    /* allocate memory */
    *value = strdup(p);
    if (*value == NULL)
        return -1;

    return 0;
}

static int
getaddrinfo_helper(const char *host_and_port, int default_port,
                   const struct addrinfo *hints,
                   struct addrinfo **aip)
{
    const char *colon, *host, *port;
    char buffer[256];

    colon = strchr(host_and_port, ':');
    if (colon == NULL) {
        snprintf(buffer, sizeof(buffer), "%d", default_port);

        host = host_and_port;
        port = buffer;
    } else {
        size_t len = colon - host_and_port;

        if (len >= sizeof(buffer)) {
            errno = ENAMETOOLONG;
            return EAI_SYSTEM;
        }

        memcpy(buffer, host_and_port, len);
        buffer[len] = 0;

        host = buffer;
        port = colon + 1;
    }

    if (strcmp(host, "*") == 0)
        host = "0.0.0.0";

    return getaddrinfo(host, port, hints, aip);
}

void
parse_cmdline(struct config *config, int argc, char **argv)
{
    int ret;
    struct addrinfo hints;
#ifdef __GLIBC__
    static const struct option long_options[] = {
        {"version", 0, 0, 'V'},
        {"verbose", 0, 0, 'v'},
        {"quiet", 0, 0, 'q'},
        {"help", 0, 0, 'h'},
        {"port", 1, 0, 'p'},
        {"chroot", 1, 0, 'r'},
        {"user", 1, 0, 'u'},
        {"logger", 1, 0, 'l'},
        {"pidfile", 1, 0, 'P'},
        {"password", 1, 0, 'w'},
        {0,0,0,0}
    };
#endif
#ifndef DISABLE_DAEMON_CODE
    struct passwd *pw;
    struct stat st;
#endif

    memset(config, 0, sizeof(*config));
    config->port = 2000;

    while (1) {
#ifdef __GLIBC__
        int option_index = 0;

        ret = getopt_long(argc, argv, "Vvqhp:r:u:Dl:w:",
                          long_options, &option_index);
#else
        ret = getopt(argc, argv, "Vvqhp:r:u:Dl:w:");
#endif
        if (ret == -1)
            break;

        switch (ret) {
        case 'V':
            printf("uoamhub v%s\n", VERSION);
            exit(0);
#ifndef DISABLE_LOGGING
        case 'v':
            verbose++;
            break;
        case 'q':
            verbose = 0;
            break;
#endif
        case 'h':
            usage();
        case 'p':
            config->port = (unsigned)strtoul(optarg, NULL, 10);
            if (config->port == 0) {
                fprintf(stderr, "invalid port specification\n");
                exit(1);
            }
            break;
        case 'w':
            if (config->password != NULL) {
                free(config->password);
                config->password = NULL;
            }

            ret = read_file_string(optarg, &config->password);
            if (ret < 0) {
                fprintf(stderr, "failed to read '%s': %s\n",
                        optarg, strerror(errno));
                exit(1);
            }

            if (config->password[0] == 0) {
                fprintf(stderr, "password in '%s' is empty\n",
                        optarg);
                exit(1);
            }

            break;
#ifndef DISABLE_DAEMON_CODE
        case 'D':
            config->no_daemon = 1;
            break;
        case 'P':
            config->pidfile = optarg;
            break;
        case 'l':
            config->logger = optarg;
            break;
        case 'r':
            ret = stat(optarg, &st);
            if (ret < 0) {
                fprintf(stderr, "failed to stat '%s': %s\n",
                        optarg, strerror(errno));
                exit(1);
            }
            if (!S_ISDIR(st.st_mode)) {
                fprintf(stderr, "not a directory: '%s'\n",
                        optarg);
                exit(1);
            }

            config->chroot_dir = optarg;
            break;
        case 'u':
            pw = getpwnam(optarg);
            if (pw == NULL) {
                fprintf(stderr, "user '%s' not found\n", optarg);
                exit(1);
            }
            if (pw->pw_uid == 0) {
                fprintf(stderr, "setuid root is not allowed\n");
                exit(1);
            }
            config->uid = pw->pw_uid;
            config->gid = pw->pw_gid;
            break;
#endif /* DISABLE_DAEMON_CODE */
        default:
            exit(1);
        }
    }

    if (optind < argc) {
        fprintf(stderr, "unrecognized argument: %s\n", argv[optind]);
        usage();
    }

#ifndef DISABLE_DAEMON_CODE
    if (geteuid() == 0 && config->uid == 0) {
        fprintf(stderr, "running uoamhub as root is a Bad Thing(TM), please use --user\n");
        exit(1);
    }
#endif /* DISABLE_DAEMON_CODE */

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_STREAM;

    ret = getaddrinfo_helper("*", config->port, &hints, &config->bind_address);
    if (ret < 0) {
        fprintf(stderr, "getaddrinfo_helper failed: %s\n",
                strerror(errno));
        exit(1);
    }
}
