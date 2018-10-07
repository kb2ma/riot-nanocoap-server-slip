/*
 * Copyright (C) 2016 Kaspar Schleiser <kaspar@schleiser.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       CoAP example server application (using nanocoap)
 *
 * @author      Kaspar Schleiser <kaspar@schleiser.de>
 * @}
 */

#include <stdio.h>

#include "net/ipv6/addr.h"
#include "net/gnrc/ipv6/nib.h"
#include "net/nanocoap.h"
#include "net/nanocoap_sock.h"

#include "xtimer.h"

#define COAP_INBUF_SIZE (256U)

#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

/* import shell commands for configuration */
extern int _gnrc_netif_config(int argc, char **argv);

int main(void)
{
    puts("RIOT nanocoap example application");

    /* nanocoap_server uses gnrc sock which uses gnrc which needs a msg queue */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);

    puts("Waiting for address autoconfiguration...");
    xtimer_sleep(3);

    /* configuration */
    /* set IP address for slip interface */
    char *addr_str = "bbbb::2";
    uint8_t prefix_len = 64;
    kernel_pid_t iface = 7;
    ipv6_addr_t addr;

    if (ipv6_addr_from_str(&addr, addr_str) == NULL) {
        puts("error: unable to parse IPv6 address.");
        return 1;
    }

    uint16_t flags = GNRC_NETIF_IPV6_ADDRS_FLAGS_STATE_VALID;
    flags |= (prefix_len << 8U);

    if (gnrc_netapi_set(iface, NETOPT_IPV6_ADDR, flags, &addr,
                        sizeof(addr)) < 0) {
        printf("error: unable to add IPv6 address\n");
        return 1;
    }

    /* set neighbor for slip interface */
    char *nbr_addr_str = "bbbb::1";
    if (ipv6_addr_from_str(&addr, nbr_addr_str) == NULL) {
        puts("error: unable to parse IPv6 address.");
        return 1;
    }
    uint8_t l2addr[GNRC_IPV6_NIB_L2ADDR_MAX_LEN];
    size_t l2addr_len = 0;
    gnrc_ipv6_nib_nc_set(&addr, iface, l2addr, l2addr_len);

    /* print network addresses */
    puts("Configured network interfaces:");
    _gnrc_netif_config(0, NULL);

    /* initialize nanocoap server instance */
    uint8_t buf[COAP_INBUF_SIZE];
    sock_udp_ep_t local = { .port=COAP_PORT, .family=AF_INET6 };
    nanocoap_server(&local, buf, sizeof(buf));

    /* should be never reached */
    return 0;
}
