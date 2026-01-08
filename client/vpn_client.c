#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if.h>
#include <netdb.h>
#include <linux/if_tun.h>
#include "aes_encrypt.h"

static volatile sig_atomic_t stop_flag = 0;
static char orig_gw[INET_ADDRSTRLEN] = "";
static char orig_ifname[IFNAMSIZ] = "";
static char saved_resolv_conf[2048];
static int saved_resolv_len = 0;

static void handle_signal(int sig) {
    stop_flag = 1;
}

static int get_default_route(char *iface, char *gateway) {
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) return -1;
    char buf[256];
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return -1;
    }
    unsigned long dest, gw;
    int flags, refcnt, use, metric, mask;
    char ifn[IFNAMSIZ];
    int ret = -1;
    while (fscanf(f, "%s %lx %lx %X %d %d %d %x %d %d %d\n",
                  ifn, &dest, &gw, &flags, &refcnt, &use, &metric, &mask,
                  &metric, &metric, &metric) == 11) {
        if (dest == 0) {
            struct in_addr gw_addr;
            gw_addr.s_addr = gw;
            if (!inet_ntop(AF_INET, &gw_addr, gateway, INET_ADDRSTRLEN)) {
                gateway[0] = '\0';
            }
            strncpy(iface, ifn, IFNAMSIZ);
            ret = 0;
            break;
        }
    }
    fclose(f);
    return ret;
}

static void enable_kill_switch(const char *server_ip) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "iptables -I OUTPUT -d %s -j ACCEPT", server_ip);
    system(cmd);
    system("iptables -I OUTPUT -o lo -j ACCEPT");
    system("iptables -I OUTPUT -o vpn1 -j ACCEPT");
    system("iptables -A OUTPUT -j DROP");
}

static void disable_kill_switch(const char *server_ip) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "iptables -D OUTPUT -d %s -j ACCEPT", server_ip);
    system(cmd);
    system("iptables -D OUTPUT -o lo -j ACCEPT");
    system("iptables -D OUTPUT -o vpn1 -j ACCEPT");
    system("iptables -D OUTPUT -j DROP");
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <tun_device> <server_ip> [<port>]\n", argv[0]);
        return 1;
    }
    const char *tun_name = argv[1];
    const char *server_host = argv[2];
    int server_port = (argc >= 4 ? atoi(argv[3]) : 5555);
    if (server_port <= 0) {
        fprintf(stderr, "[ERROR] Invalid server port\n");
        return 1;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    int tun_fd;
    struct ifreq ifr;
    if ((tun_fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("open /dev/net/tun");
        return 1;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, tun_name, IFNAMSIZ);
    if (ioctl(tun_fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(tun_fd);
        return 1;
    }
    printf("[INFO] TUN device %s created\n", tun_name);
    fflush(stdout);

    if (get_default_route(orig_ifname, orig_gw) != 0) {
        orig_ifname[0] = '\0';
        orig_gw[0] = '\0';
    }

    FILE *resolv = fopen("/etc/resolv.conf", "r");
    if (resolv) {
        saved_resolv_len = fread(saved_resolv_conf, 1, sizeof(saved_resolv_conf) - 1, resolv);
        if (saved_resolv_len < 0) saved_resolv_len = 0;
        saved_resolv_conf[saved_resolv_len] = '\0';
        fclose(resolv);
    }

    char cmd[256];

    // Bring up TUN interface
    snprintf(cmd, sizeof(cmd), "ip link set %s up", tun_name);
    system(cmd);

    // Clear any existing config
    snprintf(cmd, sizeof(cmd), "ip addr flush dev %s", tun_name);
    system(cmd);

    // Assign SLiRP-compatible guest IP and peer gateway
    snprintf(cmd, sizeof(cmd), "/sbin/ip addr add 10.0.2.15 peer 10.0.2.2 dev %s", tun_name);
    system(cmd);

    // Add default route through SLiRP gateway
    snprintf(cmd, sizeof(cmd), "/sbin/ip route add default via 10.0.2.2 dev %s", tun_name);
    system(cmd);
    // Manually add static ARP entry for SLiRP gateway (required on some kernels)
snprintf(cmd, sizeof(cmd), "/sbin/ip neigh add 10.0.2.2 lladdr 02:00:00:00:00:02 dev %s nud permanent", tun_name);
system(cmd);

    printf("[INFO] Assigned IP 10.0.2.15, gateway 10.0.2.2 via %s\n", tun_name);
    fflush(stdout);
    

    if (orig_gw[0] && orig_ifname[0]) {
        snprintf(cmd, sizeof(cmd), "ip route add %s via %s dev %s", server_host, orig_gw, orig_ifname);
        system(cmd);
    }

    // Set DNS to SLiRP's internal resolver
    resolv = fopen("/etc/resolv.conf", "w");
    if (resolv) {
        fputs("nameserver 10.0.2.3\n", resolv);
        fclose(resolv);
    }

    enable_kill_switch(server_host);
    printf("[INFO] Kill-switch enabled (non-VPN traffic blocked)\n");
    fflush(stdout);

    struct addrinfo hints, *servinfo = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(server_host, NULL, &hints, &servinfo) != 0 || !servinfo) {
        fprintf(stderr, "[ERROR] Unable to resolve server address\n");
        return 1;
    }
    ((struct sockaddr_in*)servinfo->ai_addr)->sin_port = htons(server_port);

    int sock_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    if (sock_fd < 0) {
        perror("socket");
        return 1;
    }
    if (connect(sock_fd, servinfo->ai_addr, servinfo->ai_addrlen) < 0) {
        perror("connect");
        return 1;
    }

    freeaddrinfo(servinfo);
    printf("[INFO] UDP socket connected to %s:%d\n", server_host, server_port);
    printf("[INFO] AES encryption initialized\n");
    fflush(stdout);
    aes_init();

    printf("[INFO] VPN client started, entering main loop\n");
    fflush(stdout);

    unsigned char buf[2048];
    unsigned char enc_buf[2048 + 16];
    unsigned char plain_buf[2048];

    fd_set readfds;
    int maxfd = (tun_fd > sock_fd ? tun_fd : sock_fd);
    struct timeval tv;
    time_t last_stat_time = time(NULL);
    unsigned long long total_tx = 0, total_rx = 0;
    unsigned long long prev_tx = 0, prev_rx = 0;

    while (!stop_flag) {
        FD_ZERO(&readfds);
        FD_SET(tun_fd, &readfds);
        FD_SET(sock_fd, &readfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        int n = select(maxfd + 1, &readfds, NULL, NULL, &tv);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (FD_ISSET(tun_fd, &readfds)) {
            int len = read(tun_fd, buf, sizeof(buf));
            if (len > 0) {
                          // Validate IPv4 packet before encryption
              struct iphdr *iph = (struct iphdr *)buf;
              if (iph->version != 4) {
                  fprintf(stderr, "[CLIENT WARNING] Not IPv4: version=%d, ignoring\n", iph->version);
              } else {
                  char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
                  inet_ntop(AF_INET, &iph->saddr, src, sizeof(src));
                  inet_ntop(AF_INET, &iph->daddr, dst, sizeof(dst));
                  printf("[CLIENT OUT] src=%s dst=%s proto=%d\n", src, dst, iph->protocol);
              }

                int enc_len = aes_encrypt(buf, len, enc_buf);
                send(sock_fd, enc_buf, enc_len, 0);
                total_tx += len;
            }
        }
      if (FD_ISSET(sock_fd, &readfds)) {
    ssize_t recv_len = recv(sock_fd, enc_buf, sizeof(enc_buf), 0);
    if (recv_len > 0) {
        int plain_len = aes_decrypt(enc_buf, recv_len, plain_buf);
        if (plain_len > 0) {
            struct iphdr *iph = (struct iphdr *)plain_buf;
            char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &iph->saddr, src, sizeof(src));
            inet_ntop(AF_INET, &iph->daddr, dst, sizeof(dst));
            printf("[DEBUG] Decrypted %d bytes from server\n", plain_len);
            printf("[DEBUG] IP Header: src=%s dst=%s proto=%d\n", src, dst, iph->protocol);
            write(tun_fd, plain_buf, plain_len);
            total_rx += plain_len;
        } else {
            fprintf(stderr, "[ERROR] aes_decrypt() failed (recv_len=%zd)\n", recv_len);
        }
    }
}
        time_t now = time(NULL);
        if (now - last_stat_time >= 1) {
            double tx_speed = (double)(total_tx - prev_tx) / 1024.0;
            double rx_speed = (double)(total_rx - prev_rx) / 1024.0;
            printf("STATS: Sent: %llu bytes (%.2f kB/s up), Received: %llu bytes (%.2f kB/s down)\n",
                   total_tx, tx_speed, total_rx, rx_speed);
            fflush(stdout);
            prev_tx = total_tx;
            prev_rx = total_rx;
            last_stat_time = now;
        }
    }

    close(sock_fd);
    close(tun_fd);
    disable_kill_switch(server_host);
    FILE *resolv_w = fopen("/etc/resolv.conf", "w");
    if (resolv_w) {
        if (saved_resolv_len > 0) {
            fwrite(saved_resolv_conf, 1, saved_resolv_len, resolv_w);
        } else {
            fputs("nameserver 10.0.2.3\n", resolv_w);
        }
        fclose(resolv_w);
    }
   system("/sbin/ip route del default");

if (orig_gw[0] && orig_ifname[0]) {
    snprintf(cmd, sizeof(cmd), "/sbin/ip route replace default via 10.0.2.2 dev %s", tun_name);
    system(cmd);
}

if (orig_gw[0] && orig_ifname[0]) {
    snprintf(cmd, sizeof(cmd), "/sbin/ip route del %s via %s dev %s", server_host, orig_gw, orig_ifname);
    system(cmd);
}

    return 0;
}

