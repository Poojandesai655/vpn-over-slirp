#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <poll.h>
#include "aes_encrypt.h"
#include <libslirp.h>
#include <netinet/ip.h>   // 👈 for struct iphdr

/*
 * VPN server using libslirp for NAT and gateway functionality over a UDP tunnel.
 * Receives raw IP packets from a single client via UDP, adds a dummy Ethernet header,
 * and injects into libslirp. Outgoing packets from libslirp have their Ethernet header
 * removed and are sent back to the client via UDP.
 *
 * Logging is printed to stdout for normal packet events and to stderr for errors.
 * Assumes a single client with known IP:port (configurable via command-line).
 * Uses AES encryption for packets (encrypt before sending, decrypt on receive).
 *
 */

/* Context for the VPN server state */
struct vpn_context {
    int udp_fd;                               /* UDP socket file descriptor */
    struct sockaddr_storage client_addr;      /* Client address (IPv4 or IPv6) */
    socklen_t client_addr_len;
    bool client_addr_set;
    bool slirp_arp_learned;
    struct pollfd *pollfds;                   /* Array of pollfd for poll() */
    size_t pollfds_size;
    size_t pollfds_count;
    /* Timer list for libslirp (for IPv6 Router Advertisements, etc.) */
    struct Timer {
        SlirpTimerCb cb;
        void *cb_opaque;
        int64_t expire_time;  /* expiration time (ms) */
        struct Timer *next;
    } *timers;
    Slirp *slirp;                             /* libslirp handle */
};

/* Global context and a flag for termination */
static struct vpn_context ctx;
static volatile sig_atomic_t stop_flag = 0;

/* Signal handler for graceful shutdown (SIGINT/SIGTERM) */
static void handle_signal(int signum) {
    (void)signum;
    stop_flag = 1;
}

/* libslirp callback: send an Ethernet frame to the client via UDP */
static ssize_t send_packet_cb(const void *buf, size_t len, void *opaque) {
    struct vpn_context *c = (struct vpn_context *)opaque;

    if (len < 14) {
        fprintf(stderr, "[send_packet_cb] Dropping short Ethernet frame (%zu bytes)\n", len);
        return -1;
    }

    const uint8_t *eth = (const uint8_t *)buf;
    uint16_t eth_type = (eth[12] << 8) | eth[13];
    const uint8_t *ip_payload = eth + 14;
    size_t ip_len = len - 14;

    // Debug log the Ethernet frame
    printf("[DEBUG] SLiRP Ethernet Frame (%zu bytes):\n", len);
    printf("  Dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth[0], eth[1], eth[2], eth[3], eth[4], eth[5]);
    printf("  Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth[6], eth[7], eth[8], eth[9], eth[10], eth[11]);
    printf("  Ethertype: 0x%04x\n", eth_type);

    // Only process IPv4 packets (Ethertype 0x0800)
    if (eth_type != 0x0800) {
        printf("[DEBUG] Skipping non-IPv4 packet (Ethertype 0x%04x)\n", eth_type);
        return 0;  // Not an error — just skip
    }

    if (ip_len >= sizeof(struct iphdr)) {
        const struct iphdr *iph = (const struct iphdr *)ip_payload;
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph->saddr, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &iph->daddr, dst_ip, sizeof(dst_ip));
        printf("  IP Header: src=%s dst=%s proto=%d\n", src_ip, dst_ip, iph->protocol);
    }

    if (ip_len > 2048) {
        fprintf(stderr, "[send_packet_cb] IP payload too large (%zu bytes)\n", ip_len);
        return -1;
    }

    uint8_t send_buf[2048];
    ssize_t enc_len = aes_encrypt((uint8_t *)ip_payload, (int)ip_len, send_buf);

    if (enc_len < 0) {
        fprintf(stderr, "[send_packet_cb] AES encryption failed\n");
        return -1;
    }

    if (!c->client_addr_set) {
        fprintf(stderr, "[send_packet_cb] Client address not set, cannot send packet\n");
        return -1;
    }

    ssize_t sent = sendto(c->udp_fd, send_buf, enc_len, 0,
                          (struct sockaddr *)&c->client_addr, c->client_addr_len);
    if (sent < 0) {
        perror("[send_packet_cb] sendto");
        return -1;
    }

    printf("[send_packet_cb] Sent %zd bytes to client\n", sent);
    return sent;
}


/* libslirp callback: report guest (client) misbehavior errors */
static void guest_error_cb(const char *msg, void *opaque) {
    (void)opaque;
    fprintf(stderr, "libslirp error: %s\n", msg);
}

/* libslirp callback: return current time in nanoseconds */
static int64_t clock_get_ns_cb(void *opaque) {
    (void)opaque;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* libslirp callback: create a new timer */
static void *timer_new_cb(SlirpTimerCb cb, void *cb_opaque, void *opaque) {
    struct vpn_context *c = (struct vpn_context *)opaque;
    struct Timer *t = malloc(sizeof(struct Timer));
    if (!t) return NULL;
    t->cb = cb;
    t->cb_opaque = cb_opaque;
    t->expire_time = -1;
    t->next = c->timers;
    c->timers = t;
    return t;
}

/* libslirp callback: free an existing timer */
static void timer_free_cb(void *timer, void *opaque) {
    struct vpn_context *c = (struct vpn_context *)opaque;
    struct Timer *t = (struct Timer *)timer;
    struct Timer **prev = &c->timers;
    while (*prev) {
        if (*prev == t) {
            *prev = t->next;
            break;
        }
        prev = &(*prev)->next;
    }
    free(t);
}

/* libslirp callback: modify a timer's expiration time (in milliseconds) */
static void timer_mod_cb(void *timer, int64_t expire_time, void *opaque) {
    struct Timer *t = (struct Timer *)timer;
    t->expire_time = expire_time;
}

/* libslirp callback: register a file descriptor for polling (no-op on Linux) */

static void register_poll_fd_cb(int fd, void *opaque) {
    (void)fd;
    (void)opaque;
    /* Not used in single-threaded Linux implementation */
}

/* libslirp callback: unregister a file descriptor (no-op on Linux) */
static void unregister_poll_fd_cb(int fd, void *opaque) {
    (void)fd;
    (void)opaque;
    /* Not used */
}

/* libslirp callback: I/O thread notification (no separate thread here, so no-op) */
static void notify_cb(void *opaque) {
    (void)opaque;
    /* Not needed in single-threaded context */
}

/* Callback for slirp_pollfds_fill: add a libslirp file descriptor to poll list */
static int add_poll_cb(int fd, int events, void *opaque) {
    struct vpn_context *c = (struct vpn_context *)opaque;
    if (c->pollfds_count >= c->pollfds_size) {
        size_t new_size = c->pollfds_size * 2;
        struct pollfd *new_array = realloc(c->pollfds, new_size * sizeof(struct pollfd));
        if (!new_array) {
            fprintf(stderr, "Error: pollfds realloc failed\n");
            return -1;
        }
        c->pollfds = new_array;
        c->pollfds_size = new_size;
    }
    struct pollfd *pfd = &c->pollfds[c->pollfds_count];
    pfd->fd = fd;
    pfd->events = 0;
    if (events & SLIRP_POLL_IN)  pfd->events |= POLLIN;
    if (events & SLIRP_POLL_OUT) pfd->events |= POLLOUT;
    if (events & SLIRP_POLL_PRI) pfd->events |= POLLPRI;
    /* (POLLERR and POLLHUP are handled via revents) */
    int index = (int)c->pollfds_count;
    c->pollfds_count++;
    return index;
}

/* Callback for slirp_pollfds_poll: translate revents back to libslirp flags */
static int get_revents_cb(int idx, void *opaque) {
    struct vpn_context *c = (struct vpn_context *)opaque;
    if (idx < 0 || (size_t)idx >= c->pollfds_count) {
        return 0;
    }
    short revents = c->pollfds[idx].revents;
    int slirp_revents = 0;
    if (revents & POLLIN)  slirp_revents |= SLIRP_POLL_IN;
    if (revents & POLLOUT) slirp_revents |= SLIRP_POLL_OUT;
    if (revents & POLLPRI) slirp_revents |= SLIRP_POLL_PRI;
    if (revents & POLLERR) slirp_revents |= SLIRP_POLL_ERR;
    if (revents & POLLHUP) slirp_revents |= SLIRP_POLL_HUP;
    return slirp_revents;
}

/* Clean up resources on exit */
static void cleanup(void) {
    if (ctx.slirp) {
        slirp_cleanup(ctx.slirp);
        ctx.slirp = NULL;
    }
    if (ctx.udp_fd >= 0) {
        close(ctx.udp_fd);
        ctx.udp_fd = -1;
    }
    /* Free any remaining timers */
    struct Timer *t = ctx.timers;
    while (t) {
        struct Timer *next = t->next;
        free(t);
        t = next;
    }
    ctx.timers = NULL;
    /* Free pollfds array */
    free(ctx.pollfds);
    ctx.pollfds = NULL;
    ctx.pollfds_size = ctx.pollfds_count = 0;
}

/* Usage message */
static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s <bind_ip> <bind_port> <client_ip> <client_port>\n", prog);
    fprintf(stderr, "Example: %s 0.0.0.0 5000 198.51.100.5 5000\n", prog);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <bind_ip> <bind_port>\n", argv[0]);
        return 1;
    }
    const char *bind_ip = argv[1];
    int bind_port = atoi(argv[2]);
    if (bind_port <= 0 || bind_port > 65535) {
        fprintf(stderr, "Invalid port number.\n");
        return 1;
    }

    /* Handle interrupts for graceful shutdown */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* Create UDP socket (IPv4 or IPv6 depending on bind address) */
    bool use_ipv6 = strchr(bind_ip, ':') != NULL;
    ctx.udp_fd = socket(use_ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    if (ctx.udp_fd < 0) {
        perror("socket");
        return 1;
    }
    /* Allow address reuse */
    int one = 1;
    setsockopt(ctx.udp_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    /* Bind socket to the specified IP and port */
    if (!use_ipv6) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)bind_port);
        if (inet_pton(AF_INET, bind_ip, &addr.sin_addr) <= 0) {
            fprintf(stderr, "Invalid bind IP address: %s\n", bind_ip);
            close(ctx.udp_fd);
            return 1;
        }
        if (bind(ctx.udp_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("bind");
            close(ctx.udp_fd);
            return 1;
        }
    } else {
        struct sockaddr_in6 addr6;
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons((uint16_t)bind_port);
        if (inet_pton(AF_INET6, bind_ip, &addr6.sin6_addr) <= 0) {
            fprintf(stderr, "Invalid bind IP address: %s\n", bind_ip);
            close(ctx.udp_fd);
            return 1;
        }
        if (bind(ctx.udp_fd, (struct sockaddr *)&addr6, sizeof(addr6)) < 0) {
            perror("bind");
            close(ctx.udp_fd);
            return 1;
        }
    }

    ctx.client_addr_set = false;
    ctx.slirp_arp_learned = false;  // ✅ Initialize ARP flag

    /* Set UDP socket non-blocking for safe polling of multiple packets */
    int flags = fcntl(ctx.udp_fd, F_GETFL, 0);
    if (flags != -1) {
        fcntl(ctx.udp_fd, F_SETFL, flags | O_NONBLOCK);
    }

    /* Configure libslirp (network parameters) */
    SlirpConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.version = 1;
    cfg.restricted = 0;                   /* allow internet access */
    cfg.in_enabled = 1;                   /* enable IPv4 */
    inet_pton(AF_INET, "10.0.2.0", &cfg.vnetwork);
    inet_pton(AF_INET, "255.255.255.0", &cfg.vnetmask);
    inet_pton(AF_INET, "10.0.2.2", &cfg.vhost);      /* Host (gateway) IP in guest network */
    cfg.in6_enabled = 1;                  /* enable IPv6 */
    inet_pton(AF_INET6, "fd00::", &cfg.vprefix_addr6);
    cfg.vprefix_len = 64;
    inet_pton(AF_INET6, "fd00::2", &cfg.vhost6);     /* Host (gateway) IPv6 */
    cfg.vhostname = NULL;
    cfg.tftp_server_name = NULL;
    cfg.tftp_path = NULL;
    cfg.bootfile = NULL;
    inet_pton(AF_INET, "10.0.2.15", &cfg.vdhcp_start); /* DHCP pool start */
    inet_pton(AF_INET, "10.0.2.3", &cfg.vnameserver);  /* DNS server (guest sees 10.0.2.3) */
    inet_pton(AF_INET6, "fd00::3", &cfg.vnameserver6);
    cfg.vdnssearch = NULL;
    cfg.vdomainname = NULL;
    cfg.if_mtu = 1500;
    cfg.if_mru = 1500;
    cfg.disable_host_loopback = 1;        /* prevent guest from connecting to host loopback */

    /* Set up libslirp callbacks */
    SlirpCb cb;
    memset(&cb, 0, sizeof(cb));
    cb.send_packet = send_packet_cb;
    cb.guest_error = guest_error_cb;
    cb.clock_get_ns = clock_get_ns_cb;
    cb.timer_new = timer_new_cb;
    cb.timer_free = timer_free_cb;
    cb.timer_mod = timer_mod_cb;
    cb.register_poll_fd = register_poll_fd_cb;
    cb.unregister_poll_fd = unregister_poll_fd_cb;
    cb.notify = notify_cb;
    /* (Other callbacks like timer_new_opaque are not used) */

    ctx.slirp = slirp_new(&cfg, &cb, &ctx);
    if (!ctx.slirp) {
        fprintf(stderr, "Error: slirp_new failed\n");
        cleanup();
        return 1;
    }

    printf("VPN server started on %s:%d, waiting for client to connect...\n",
           bind_ip, bind_port);

    /* Allocate initial pollfd array (for UDP socket + slirp fds) */
    ctx.pollfds_size = 16;
    ctx.pollfds_count = 0;
    ctx.pollfds = calloc(ctx.pollfds_size, sizeof(struct pollfd));
    if (!ctx.pollfds) {
        fprintf(stderr, "Error: memory allocation failed\n");
        cleanup();
        return 1;
    }

    /* Main event loop */
    int64_t now_ms;
    while (!stop_flag) {
        /* Prepare pollfd list for poll() */
        ctx.pollfds_count = 0;
        ctx.pollfds[ctx.pollfds_count].fd = ctx.udp_fd;
        ctx.pollfds[ctx.pollfds_count].events = POLLIN;
        ctx.pollfds[ctx.pollfds_count].revents = 0;
        ctx.pollfds_count++;

        /* Get libslirp fds and timeout */
        uint32_t slirp_timeout = 0;
        slirp_pollfds_fill(ctx.slirp, &slirp_timeout, add_poll_cb, &ctx);
        uint32_t timeout_ms = slirp_timeout;
        now_ms = clock_get_ns_cb(NULL) / 1000000;
        bool immediate = false;
        /* Check timers for sooner timeouts */
        for (struct Timer *t = ctx.timers; t; t = t->next) {
            if (t->expire_time >= 0) {
                if (t->expire_time <= now_ms) {
                    immediate = true;
                } else {
                    uint32_t wait = (uint32_t)(t->expire_time - now_ms);
                    if (!timeout_ms || wait < timeout_ms) {
                        timeout_ms = wait;
                    }
                }
            }
        }
        if (immediate) {
            timeout_ms = 0;
        }

        int nfds = (int)ctx.pollfds_count;
        int ret = poll(ctx.pollfds, nfds, timeout_ms);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }
        slirp_pollfds_poll(ctx.slirp, (ret < 0 ? 1 : 0), get_revents_cb, &ctx);

        /* Handle incoming UDP packets from client */
        if (ctx.pollfds[0].revents & POLLIN) {
            uint8_t recv_buf[4096];
            struct sockaddr_storage src_addr;
            socklen_t addr_len = sizeof(src_addr);
            ssize_t nbytes;
            /* Read all available datagrams (non-blocking) */
            while ((nbytes = recvfrom(ctx.udp_fd, recv_buf, sizeof(recv_buf), 0,
                                       (struct sockaddr *)&src_addr, &addr_len)) > 0) {
                                            if (!ctx.client_addr_set) {
                                   ctx.client_addr = src_addr;
                                   ctx.client_addr_len = addr_len;
                                   ctx.client_addr_set = true;

                                   char cli_ip_str[INET6_ADDRSTRLEN];
                                   uint16_t cli_port = 0;
                                   if (src_addr.ss_family == AF_INET) {
                                       struct sockaddr_in *sin = (struct sockaddr_in *)&src_addr;
                                       inet_ntop(AF_INET, &sin->sin_addr, cli_ip_str, sizeof(cli_ip_str));
                                       cli_port = ntohs(sin->sin_port);
                                   } else if (src_addr.ss_family == AF_INET6) {
                                       struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&src_addr;
                                       inet_ntop(AF_INET6, &sin6->sin6_addr, cli_ip_str, sizeof(cli_ip_str));
                                       cli_port = ntohs(sin6->sin6_port);
                                   } else {
                                       strcpy(cli_ip_str, "Unknown");
                                   }
                                   printf("Client address %s:%u detected\n", cli_ip_str, cli_port);
                               } else {
                bool same = false;
                if (src_addr.ss_family == AF_INET && ctx.client_addr.ss_family == AF_INET) {
                    struct sockaddr_in *sin = (struct sockaddr_in *)&src_addr;
                    struct sockaddr_in *csin = (struct sockaddr_in *)&ctx.client_addr;
                    if (sin->sin_addr.s_addr == csin->sin_addr.s_addr && sin->sin_port == csin->sin_port) {
                        same = true;
                    }
                } else if (src_addr.ss_family == AF_INET6 && ctx.client_addr.ss_family == AF_INET6) {
                    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&src_addr;
                    struct sockaddr_in6 *csin6 = (struct sockaddr_in6 *)&ctx.client_addr;
                    if (memcmp(&sin6->sin6_addr, &csin6->sin6_addr, sizeof(struct in6_addr)) == 0 &&
                        sin6->sin6_port == csin6->sin6_port) {
                        same = true;
                    }
                }
                if (!same) {
                    char src_ip_str[INET6_ADDRSTRLEN];
                    uint16_t src_port = 0;
                    if (src_addr.ss_family == AF_INET) {
                        struct sockaddr_in *sin = (struct sockaddr_in *)&src_addr;
                        inet_ntop(AF_INET, &sin->sin_addr, src_ip_str, sizeof(src_ip_str));
                        src_port = ntohs(sin->sin_port);
                    } else if (src_addr.ss_family == AF_INET6) {
                        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&src_addr;
                        inet_ntop(AF_INET6, &sin6->sin6_addr, src_ip_str, sizeof(src_ip_str));
                        src_port = ntohs(sin6->sin6_port);
                    } else {
                        strcpy(src_ip_str, "Unknown");
                    }
                    printf("Ignoring packet from unknown source %s:%u\n", src_ip_str, src_port);
                    continue;
                }
            }
                if (nbytes <= 0) {
                    continue;
                }
                printf("Received packet from client (%zd bytes)\n", nbytes);
                /* Decrypt the received payload */
                uint8_t plain_buf[4096];
                ssize_t plain_len = aes_decrypt(recv_buf, (int)nbytes, plain_buf);
                if (plain_len < 0) {
                    fprintf(stderr, "Error: packet decryption failed (dropping packet)\n");
                    continue;
                }
                /* Prepend dummy Ethernet header for libslirp */
                if (plain_len + 14 > sizeof(plain_buf)) {
                    fprintf(stderr, "Error: dropping packet, size %zd too large for Ethernet frame\n", plain_len);
                    continue;
                }
                uint8_t *eth_frame = plain_buf;
                /* Shift IP payload forward to make room for Ethernet header */
                memmove(eth_frame + 14, eth_frame, plain_len);
                /* Dummy MAC addresses (host MAC and client MAC) */
                uint8_t client_mac[6]  = {0x02,0x00,0x00,0x00,0x00,0x01};
                uint8_t gateway_mac[6] = {0x02,0x00,0x00,0x00,0x00,0x02};
                memcpy(&eth_frame[0],  gateway_mac, 6);  // Destination MAC
                memcpy(&eth_frame[6],  client_mac,  6);  // Source MAC
                /* Set Ethertype based on IP version */
                struct iphdr *iph = (struct iphdr *)(eth_frame + 14);
                char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &iph->saddr, src, sizeof(src));
                inet_ntop(AF_INET, &iph->daddr, dst, sizeof(dst));
                printf("[RECV] Decrypted IP: src=%s dst=%s proto=%d\n", src, dst, iph->protocol);

                if (iph->version != 4 && iph->version != 6) {
                    fprintf(stderr, "[ERROR] Invalid IP version (%d), dropping packet\n", iph->version);
                    continue;
                }
                if (iph->version == 4) {
                    eth_frame[12] = 0x08;
                    eth_frame[13] = 0x00;
                } else {
                    eth_frame[12] = 0x86;
                    eth_frame[13] = 0xDD;
                }
                if (!ctx.slirp_arp_learned && iph->version == 4 && iph->saddr != 0) {
                    ctx.slirp_arp_learned = true;
                    uint32_t client_ip = iph->saddr;
                
                    uint8_t arp_frame[60];
                    memset(arp_frame, 0, sizeof(arp_frame));
                    
                    // Ethernet header
                    memcpy(arp_frame, gateway_mac, 6);          // Destination MAC (to gateway)
                    memcpy(arp_frame + 6, client_mac, 6);       // Source MAC (client)
                    arp_frame[12] = 0x08; arp_frame[13] = 0x06; // Ethertype = ARP
                
                    // ARP payload
                    arp_frame[14] = 0x00; arp_frame[15] = 0x01; // HTYPE: Ethernet
                    arp_frame[16] = 0x08; arp_frame[17] = 0x00; // PTYPE: IPv4
                    arp_frame[18] = 6;    // HLEN
                    arp_frame[19] = 4;    // PLEN
                    arp_frame[20] = 0x00; arp_frame[21] = 0x02; // Opcode: ARP Reply
                    memcpy(&arp_frame[22], client_mac, 6);      // Sender MAC
                    memcpy(&arp_frame[28], &client_ip, 4);      // Sender IP
                    memcpy(&arp_frame[32], gateway_mac, 6);     // Target MAC
                    uint8_t gw_ip[4] = {10, 0, 2, 2};           // Target IP (SLiRP gateway)
                    memcpy(&arp_frame[38], gw_ip, 4);
                
                    slirp_input(ctx.slirp, arp_frame, sizeof(arp_frame));
                    printf("[INFO] Injected synthetic ARP reply to SLiRP for IP %u.%u.%u.%u\n",
                           (client_ip      ) & 0xFF,
                           (client_ip >>  8) & 0xFF,
                           (client_ip >> 16) & 0xFF,
                           (client_ip >> 24) & 0xFF);
                }
                printf("[DEBUG] Injected ARP reply into SLiRP\n");

                int frame_len = (int)plain_len + 14;
                /* Feed the Ethernet frame into libslirp */
                slirp_input(ctx.slirp, eth_frame, frame_len);
            }
            if (nbytes < 0 && errno != EWOULDBLOCK && errno != EAGAIN) {
                perror("recvfrom");
            }
        }

        /* Handle any expired libslirp timers (e.g., send router advertisements) */
        now_ms = clock_get_ns_cb(NULL) / 1000000;
        for (struct Timer *t = ctx.timers; t; t = t->next) {
            if (t->expire_time >= 0 && t->expire_time <= now_ms) {
                t->expire_time = -1;
                if (t->cb) {
                    t->cb(t->cb_opaque);
                }
            }
        }
    }

    printf("Shutting down VPN server...\n");
    cleanup();
    return 0;
}

