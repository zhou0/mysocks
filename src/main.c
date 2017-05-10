/* Copyright StrongLoop, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32) && (defined(__unix__) || defined(__unix) || (defined(__APPLE__) && defined(__MACH__)))
/* UNIX-style OS. ------------------------------------------- */
#include <unistd.h>  /* getopt */
#endif

#include "defs.h"
#ifdef WITH_OPENSSL
#include <openssl/opensslv.h>
#include "cipher-openssl.h"
#else
#include "cipher.h"
#endif
//#ifdef _MSC_VER
//#pragma comment( lib, "uv.lib" )
//#endif
#define DEFAULT_BIND_HOST     "127.0.0.1"
#define DEFAULT_BIND_PORT     1491
#define DEFAULT_IDLE_TIMEOUT  (60 * 1000)

server_config config;

static void parse_opts(int argc, char **argv);
static void usage(void);

static const char *progname = __FILE__; /* Reset in main(). */

int main(int argc, char **argv)
{
    int err;

    progname = argv[0];
    memset(&config, 0, sizeof (config));
    config.bind_host = DEFAULT_BIND_HOST;
    config.bind_port = DEFAULT_BIND_PORT;
    config.idle_timeout = DEFAULT_IDLE_TIMEOUT;
    parse_opts(argc, argv);
    initialize_cipher();
    err = server_run(&config, uv_default_loop());
    if (err)
    {
        exit(1);
    }
    cleanup_cipher();
    return 0;
}

const char *_getprogname(void)
{
    return progname;
}

static void parse_opts(int argc, char **argv)
{
    int opt;

    while (-1 != (opt = getopt(argc, argv, "b:hk:l:m:p:s:")))
    {
        switch (opt)
        {
        case 'b':
            config.bind_host = optarg;
            break;
        case 'k':
            config.password = optarg;
            break;
        case 'l':
#ifdef _MSC_VER
            if (1 != sscanf_s(optarg, "%hu", &config.bind_port))
            {
#else
            if (1 != sscanf(optarg, "%hu", &config.bind_port))
            {
#endif
                pr_err("bad port number: %s", optarg);
                usage();
            }
            if (config.bind_port <= 1024)
            {
                pr_err("can not bind to port number %s with no  root privilege", optarg);
                usage();
            }
            break;
        case 'm':
            config.method = optarg;
            break;
        case 'p':
#ifdef _MSC_VER
            if (1 != sscanf_s(optarg, "%hu", &(config.remote_port)))
            {
#else
            if (1 != sscanf(optarg, "%hu", &(config.remote_port)))
            {
#endif
                //          pr_err("bad port number: %s", optarg);
                pr_err("bad port number: %s", optarg);
                usage();
            }
            break;
        case 's':
            config.remote_host = optarg;
            break;
        default:
            usage();
        }
    }
    if (!config.remote_host || !config.remote_port || !config.method || !config.password) usage();
}

static void usage(void)
{

    printf("\n"
           "This is MySocks project, the lightweight multi-platform shadowsocks client and server,version 0.5, subversion 6 (v0.5.6). Copyright 2017, Li ZHOU\n"
           "\n"
           "Usage:%s [-b <local_host>] [-h] -k <password> -m <encrypt_method> [-l <port>] -p <remote_port> -s <remote_host>\n"
           "\n"
           "Mandatory Options:\n"
           "  -k <password>\t\tpassword of your remote server\n"
           "  -m <encrypt_method>\tencrypt method,must be one of:\n"
#ifdef WITH_OPENSSL
           "\t\t\taes-128-cfb,aes-128-ctr,aes-128-ofb\n"
           "\t\t\taes-192-cfb,aes-192-ctr,aes-192-ofb\n"
           "\t\t\taes-256-cfb,aes-256-ctr,aes-256-ofb\n"
           "\t\t\tcamellia-128-cfb,camellia-128-ofb\n"
           "\t\t\tcamellia-192-cfb,camellia-192-ofb\n"
           "\t\t\tcamellia-256-cfb,camellia-256-ofb\n"
//#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
//	   "\t\t\tchacha20-ietf,chacha2-ietf-poly1305\n" 
//#endif
#endif
#ifdef WITH_WOLFSSL
           "\t\t\taes-128-cbc,aes-128-ccm,aes-128-ctr,aes-128-gcm\n"
	   "\t\t\taes-192-cbc,aes-192-ccm,aes-192-ctr,aes-192-gcm\n"
           "\t\t\taes-256-cbc,aes-256-ccm,aes-256-ctr,aes-256-gcm\n"
           "\t\t\tcamellia-128-cbc,camellia-256-cbc\n"
           "\t\t\tchacha20-ietf,hc-128,rabbit\n"
	   "\t\t\tchacha20-ietf-poly1305\n" 
#endif
           "\t\t\trc4-md5\n"
           "  -p <remote_port>\tport number of your remote server\n"
           "  -s <remote_host>\thostname or ip address of your remote server\n"
           "Optional Options:\n"
           "  -b <local_host>\tlocal hostname or ip address bind to,default localhost\n"
           "  -h\t\t\tshow this help message.\n"
           "  -l <local_port>\tlocal port number listen to,default 1491\n"
           "\n"
           "MySocks is open source software. For more information, please visit MySocks project website at https://github.com/zhou0/mysocks \n",
           progname);
    exit(1);
}
