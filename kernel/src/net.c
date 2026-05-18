#include "net.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "console.h"
#include "string.h"
#include "virtio_net.h"

#define ETH_TYPE_IPV4 0x0800u
#define ETH_TYPE_ARP 0x0806u
#define IP_PROTO_ICMP 1u
#define IP_PROTO_TCP 6u
#define IP_PROTO_UDP 17u

#define DHCP_CLIENT_PORT 68u
#define DHCP_SERVER_PORT 67u
#define DHCP_MAGIC 0x63825363u
#define DHCP_XID 0x56494245u

#define MAX_ARP_ENTRIES 16
#define MAX_UDP_BINDINGS 32
#define UDP_QUEUE_PACKETS 16
#define UDP_PAYLOAD_CAPACITY 1536u
#define MAX_TCP_CONNECTIONS 32
#define TCP_BUFFER_CAPACITY 65536u
#define MAX_RAW_ICMP_SOCKETS 16
#define RAW_ICMP_QUEUE_PACKETS 16
#define RAW_ICMP_PACKET_CAPACITY 1536u
#define TCP_SYN 0x02u
#define TCP_FIN 0x01u
#define TCP_RST 0x04u
#define TCP_PSH 0x08u
#define TCP_ACK 0x10u

struct eth_hdr {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
} __attribute__((packed));

struct arp_packet {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t sha[6];
    uint32_t spa;
    uint8_t tha[6];
    uint32_t tpa;
} __attribute__((packed));

struct ipv4_hdr {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t proto;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
} __attribute__((packed));

struct udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
} __attribute__((packed));

struct icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
} __attribute__((packed));

struct tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t data_off;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} __attribute__((packed));

struct dhcp_packet {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint32_t magic;
    uint8_t options[312];
} __attribute__((packed));

struct arp_entry {
    bool used;
    uint32_t ip;
    uint8_t mac[6];
};

struct udp_packet {
    bool used;
    uint32_t src_ip;
    uint16_t src_port;
    size_t len;
    uint8_t data[UDP_PAYLOAD_CAPACITY];
};

struct udp_binding {
    bool used;
    uint16_t port;
    uint16_t head;
    uint16_t count;
    struct udp_packet packets[UDP_QUEUE_PACKETS];
};

enum tcp_state {
    TCP_CLOSED = 0,
    TCP_SYN_SENT,
    TCP_ESTABLISHED,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
};

struct tcp_connection {
    bool used;
    enum tcp_state state;
    uint16_t local_port;
    uint32_t remote_ip;
    uint16_t remote_port;
    uint32_t seq;
    uint32_t ack;
    uint16_t remote_window;
    uint8_t remote_mac[6];
    size_t read_off;
    size_t read_size;
    uint8_t read_buf[TCP_BUFFER_CAPACITY];
};

struct raw_icmp_packet {
    bool used;
    uint32_t src_ip;
    size_t len;
    uint8_t data[RAW_ICMP_PACKET_CAPACITY];
};

struct raw_icmp_socket {
    bool used;
    uint16_t head;
    uint16_t count;
    struct raw_icmp_packet packets[RAW_ICMP_QUEUE_PACKETS];
};

static struct net_ipv4_config g_config;
static net_link_send_fn g_send;
static struct arp_entry g_arp[MAX_ARP_ENTRIES];
static struct udp_binding g_udp[MAX_UDP_BINDINGS];
static struct tcp_connection g_tcp[MAX_TCP_CONNECTIONS];
static struct raw_icmp_socket g_raw_icmp[MAX_RAW_ICMP_SOCKETS];
static uint16_t g_next_port = 49152u;
static uint16_t g_ip_id = 1u;
static uint32_t g_tcp_seed = 0x56780000u;
static bool g_dhcp_running;
static uint8_t g_dhcp_server_mac[6];
static uint32_t g_dhcp_server_ip;

static uint16_t bswap16(uint16_t value) {
    return (uint16_t)((value << 8) | (value >> 8));
}

static uint32_t bswap32(uint32_t value) {
    return ((value & 0x000000FFu) << 24) | ((value & 0x0000FF00u) << 8) | ((value & 0x00FF0000u) >> 8) |
           ((value & 0xFF000000u) >> 24);
}

static uint16_t htons(uint16_t value) {
    return bswap16(value);
}

static uint16_t ntohs(uint16_t value) {
    return bswap16(value);
}

static uint32_t htonl(uint32_t value) {
    return bswap32(value);
}

static uint32_t ntohl(uint32_t value) {
    return bswap32(value);
}

static uint32_t ip4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | d;
}

static uint16_t checksum_finish(uint32_t sum) {
    while ((sum >> 16) != 0u) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static uint32_t checksum_add(uint32_t sum, const void* data, size_t len) {
    const uint8_t* bytes = (const uint8_t*)data;
    while (len >= 2u) {
        sum += (uint16_t)((uint16_t)bytes[0] << 8) | bytes[1];
        bytes += 2;
        len -= 2;
    }
    if (len != 0u) {
        sum += (uint16_t)((uint16_t)bytes[0] << 8);
    }
    return sum;
}

static uint16_t checksum(const void* data, size_t len) {
    return checksum_finish(checksum_add(0, data, len));
}

static bool mac_is_zero(const uint8_t mac[6]) {
    return mac[0] == 0u && mac[1] == 0u && mac[2] == 0u && mac[3] == 0u && mac[4] == 0u && mac[5] == 0u;
}

static void arp_remember(uint32_t ip, const uint8_t mac[6]) {
    if (ip == 0u || mac_is_zero(mac)) {
        return;
    }
    for (size_t i = 0; i < MAX_ARP_ENTRIES; ++i) {
        if (g_arp[i].used && g_arp[i].ip == ip) {
            memcpy(g_arp[i].mac, mac, 6);
            return;
        }
    }
    for (size_t i = 0; i < MAX_ARP_ENTRIES; ++i) {
        if (!g_arp[i].used) {
            g_arp[i].used = true;
            g_arp[i].ip = ip;
            memcpy(g_arp[i].mac, mac, 6);
            return;
        }
    }
    g_arp[0].ip = ip;
    memcpy(g_arp[0].mac, mac, 6);
}

static bool arp_lookup(uint32_t ip, uint8_t mac[6]) {
    for (size_t i = 0; i < MAX_ARP_ENTRIES; ++i) {
        if (g_arp[i].used && g_arp[i].ip == ip) {
            memcpy(mac, g_arp[i].mac, 6);
            return true;
        }
    }
    return false;
}

static bool send_ethernet(const uint8_t dst[6], uint16_t type, const void* payload, size_t payload_len) {
    uint8_t frame[1514];
    if (payload_len + sizeof(struct eth_hdr) > sizeof(frame) || g_send == NULL) {
        return false;
    }
    struct eth_hdr* eth = (struct eth_hdr*)frame;
    memcpy(eth->dst, dst, 6);
    memcpy(eth->src, g_config.mac, 6);
    eth->type = htons(type);
    memcpy(frame + sizeof(*eth), payload, payload_len);
    return g_send(frame, sizeof(*eth) + payload_len);
}

static void send_arp_request(uint32_t ip) {
    static const uint8_t broadcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    struct arp_packet arp;
    memset(&arp, 0, sizeof(arp));
    arp.htype = htons(1u);
    arp.ptype = htons(ETH_TYPE_IPV4);
    arp.hlen = 6u;
    arp.plen = 4u;
    arp.oper = htons(1u);
    memcpy(arp.sha, g_config.mac, 6);
    arp.spa = htonl(g_config.address);
    arp.tpa = htonl(ip);
    (void)send_ethernet(broadcast, ETH_TYPE_ARP, &arp, sizeof(arp));
}

static void send_arp_reply(const uint8_t dst_mac[6], uint32_t dst_ip) {
    struct arp_packet arp;
    memset(&arp, 0, sizeof(arp));
    arp.htype = htons(1u);
    arp.ptype = htons(ETH_TYPE_IPV4);
    arp.hlen = 6u;
    arp.plen = 4u;
    arp.oper = htons(2u);
    memcpy(arp.sha, g_config.mac, 6);
    arp.spa = htonl(g_config.address);
    memcpy(arp.tha, dst_mac, 6);
    arp.tpa = htonl(dst_ip);
    (void)send_ethernet(dst_mac, ETH_TYPE_ARP, &arp, sizeof(arp));
}

static uint32_t route_ip(uint32_t dst_ip) {
    if (g_config.gateway != 0u && (dst_ip & g_config.netmask) != (g_config.address & g_config.netmask)) {
        return g_config.gateway;
    }
    return dst_ip;
}

static bool resolve_mac(uint32_t dst_ip, uint8_t mac[6]) {
    uint32_t next_hop = route_ip(dst_ip);
    if (arp_lookup(next_hop, mac)) {
        return true;
    }
    send_arp_request(next_hop);
    for (uint32_t i = 0; i < 200000u; ++i) {
        virtio_net_poll();
        if (arp_lookup(next_hop, mac)) {
            return true;
        }
        __asm__ volatile("pause" : : : "memory");
    }
    return false;
}

static bool send_ipv4(uint32_t dst_ip, uint8_t proto, const void* payload, size_t payload_len) {
    uint8_t frame[1500];
    if (!g_config.configured || payload_len + sizeof(struct ipv4_hdr) > sizeof(frame)) {
        return false;
    }
    uint8_t mac[6];
    if (!resolve_mac(dst_ip, mac)) {
        return false;
    }
    struct ipv4_hdr* ip = (struct ipv4_hdr*)frame;
    memset(ip, 0, sizeof(*ip));
    ip->ver_ihl = 0x45u;
    ip->total_len = htons((uint16_t)(sizeof(*ip) + payload_len));
    ip->id = htons(g_ip_id++);
    ip->frag_off = htons(0x4000u);
    ip->ttl = 64u;
    ip->proto = proto;
    ip->src = htonl(g_config.address);
    ip->dst = htonl(dst_ip);
    ip->checksum = htons(checksum(ip, sizeof(*ip)));
    memcpy(frame + sizeof(*ip), payload, payload_len);
    return send_ethernet(mac, ETH_TYPE_IPV4, frame, sizeof(*ip) + payload_len);
}

static uint16_t transport_checksum(uint32_t src_ip, uint32_t dst_ip, uint8_t proto, const void* packet, size_t packet_len) {
    uint32_t sum = 0;
    uint32_t src = htonl(src_ip);
    uint32_t dst = htonl(dst_ip);
    uint16_t len = htons((uint16_t)packet_len);
    sum = checksum_add(sum, &src, sizeof(src));
    sum = checksum_add(sum, &dst, sizeof(dst));
    uint8_t zero_proto[2] = { 0u, proto };
    sum = checksum_add(sum, zero_proto, sizeof(zero_proto));
    sum = checksum_add(sum, &len, sizeof(len));
    sum = checksum_add(sum, packet, packet_len);
    return checksum_finish(sum);
}

static bool send_udp_raw(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, const void* data, size_t len,
                         bool broadcast) {
    uint8_t packet[1500];
    if (len + sizeof(struct udp_hdr) > sizeof(packet)) {
        return false;
    }
    struct udp_hdr* udp = (struct udp_hdr*)packet;
    udp->src_port = htons(src_port);
    udp->dst_port = htons(dst_port);
    udp->len = htons((uint16_t)(sizeof(*udp) + len));
    udp->checksum = 0u;
    memcpy(packet + sizeof(*udp), data, len);
    if (!broadcast) {
        udp->checksum = htons(transport_checksum(src_ip, dst_ip, IP_PROTO_UDP, packet, sizeof(*udp) + len));
        if (udp->checksum == 0u) {
            udp->checksum = 0xFFFFu;
        }
    }
    bool ok;
    if (broadcast) {
        static const uint8_t bcast_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
        uint8_t ipbuf[1500];
        struct ipv4_hdr* ip = (struct ipv4_hdr*)ipbuf;
        memset(ip, 0, sizeof(*ip));
        ip->ver_ihl = 0x45u;
        ip->total_len = htons((uint16_t)(sizeof(*ip) + sizeof(*udp) + len));
        ip->id = htons(g_ip_id++);
        ip->frag_off = htons(0x4000u);
        ip->ttl = 64u;
        ip->proto = IP_PROTO_UDP;
        ip->src = htonl(src_ip);
        ip->dst = htonl(dst_ip);
        ip->checksum = htons(checksum(ip, sizeof(*ip)));
        memcpy(ipbuf + sizeof(*ip), packet, sizeof(*udp) + len);
        ok = send_ethernet(bcast_mac, ETH_TYPE_IPV4, ipbuf, sizeof(*ip) + sizeof(*udp) + len);
    } else {
        ok = send_ipv4(dst_ip, IP_PROTO_UDP, packet, sizeof(*udp) + len);
    }
    return ok;
}

static struct udp_binding* find_udp_binding(uint16_t port) {
    for (size_t i = 0; i < MAX_UDP_BINDINGS; ++i) {
        if (g_udp[i].used && g_udp[i].port == port) {
            return &g_udp[i];
        }
    }
    return NULL;
}

static void udp_deliver(uint32_t src_ip, uint16_t src_port, uint16_t dst_port, const void* data, size_t len) {
    struct udp_binding* binding = find_udp_binding(dst_port);
    if (binding == NULL || len > UDP_PAYLOAD_CAPACITY || binding->count >= UDP_QUEUE_PACKETS) {
        return;
    }
    uint16_t idx = (uint16_t)((binding->head + binding->count) % UDP_QUEUE_PACKETS);
    struct udp_packet* packet = &binding->packets[idx];
    packet->used = true;
    packet->src_ip = src_ip;
    packet->src_port = src_port;
    packet->len = len;
    memcpy(packet->data, data, len);
    binding->count++;
}

int net_udp_bind(uint16_t requested_port) {
    if (requested_port == 0u) {
        requested_port = net_ephemeral_port();
    }
    if (find_udp_binding(requested_port) != NULL) {
        return -1;
    }
    for (size_t i = 0; i < MAX_UDP_BINDINGS; ++i) {
        if (!g_udp[i].used) {
            memset(&g_udp[i], 0, sizeof(g_udp[i]));
            g_udp[i].used = true;
            g_udp[i].port = requested_port;
            return (int)requested_port;
        }
    }
    return -1;
}

int net_udp_send(uint16_t local_port, uint32_t dst_ip, uint16_t dst_port, const void* data, size_t len) {
    return send_udp_raw(g_config.address, dst_ip, local_port, dst_port, data, len, false) ? (int)len : -1;
}

int net_udp_recv(uint16_t local_port, void* data, size_t len, uint32_t* src_ip, uint16_t* src_port) {
    struct udp_binding* binding = find_udp_binding(local_port);
    if (binding == NULL || binding->count == 0u) {
        return -1;
    }
    struct udp_packet* packet = &binding->packets[binding->head];
    size_t n = len < packet->len ? len : packet->len;
    memcpy(data, packet->data, n);
    if (src_ip != NULL) {
        *src_ip = packet->src_ip;
    }
    if (src_port != NULL) {
        *src_port = packet->src_port;
    }
    memset(packet, 0, sizeof(*packet));
    binding->head = (uint16_t)((binding->head + 1u) % UDP_QUEUE_PACKETS);
    binding->count--;
    return (int)n;
}

size_t net_udp_pending(uint16_t local_port) {
    struct udp_binding* binding = find_udp_binding(local_port);
    if (binding == NULL || binding->count == 0u) {
        return 0u;
    }
    return binding->packets[binding->head].len;
}

uint16_t net_ephemeral_port(void) {
    uint16_t port = g_next_port++;
    if (g_next_port < 49152u) {
        g_next_port = 49152u;
    }
    return port;
}

static void dhcp_add_option(uint8_t* opts, size_t* off, uint8_t type, const void* data, uint8_t len) {
    opts[(*off)++] = type;
    opts[(*off)++] = len;
    memcpy(&opts[*off], data, len);
    *off += len;
}

static void dhcp_send(uint8_t msg_type, uint32_t requested_ip, uint32_t server_id) {
    struct dhcp_packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.op = 1u;
    pkt.htype = 1u;
    pkt.hlen = 6u;
    pkt.xid = htonl(DHCP_XID);
    pkt.flags = htons(0x8000u);
    memcpy(pkt.chaddr, g_config.mac, 6);
    pkt.magic = htonl(DHCP_MAGIC);
    size_t off = 0;
    dhcp_add_option(pkt.options, &off, 53u, &msg_type, 1u);
    if (requested_ip != 0u) {
        uint32_t req = htonl(requested_ip);
        dhcp_add_option(pkt.options, &off, 50u, &req, 4u);
    }
    if (server_id != 0u) {
        uint32_t sid = htonl(server_id);
        dhcp_add_option(pkt.options, &off, 54u, &sid, 4u);
    }
    uint8_t params[] = { 1u, 3u, 6u };
    dhcp_add_option(pkt.options, &off, 55u, params, sizeof(params));
    pkt.options[off++] = 255u;
    (void)send_udp_raw(0u, 0xFFFFFFFFu, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, &pkt, offsetof(struct dhcp_packet, options) + off, true);
}

static void handle_dhcp(const uint8_t src_mac[6], uint32_t src_ip, const void* data, size_t len) {
    if (len < offsetof(struct dhcp_packet, options) || !g_dhcp_running) {
        return;
    }
    const struct dhcp_packet* pkt = (const struct dhcp_packet*)data;
    if (pkt->op != 2u || ntohl(pkt->xid) != DHCP_XID || ntohl(pkt->magic) != DHCP_MAGIC || memcmp(pkt->chaddr, g_config.mac, 6) != 0) {
        return;
    }
    uint8_t type = 0;
    uint32_t server_id = src_ip;
    uint32_t mask = 0;
    uint32_t router = 0;
    uint32_t dns = 0;
    size_t options_len = len - offsetof(struct dhcp_packet, options);
    size_t off = 0;
    while (off < options_len) {
        uint8_t opt = pkt->options[off++];
        if (opt == 0u) {
            continue;
        }
        if (opt == 255u || off >= options_len) {
            break;
        }
        uint8_t opt_len = pkt->options[off++];
        if (off + opt_len > options_len) {
            break;
        }
        const uint8_t* val = &pkt->options[off];
        if (opt == 53u && opt_len >= 1u) {
            type = val[0];
        } else if (opt == 54u && opt_len >= 4u) {
            memcpy(&server_id, val, 4);
            server_id = ntohl(server_id);
        } else if (opt == 1u && opt_len >= 4u) {
            memcpy(&mask, val, 4);
            mask = ntohl(mask);
        } else if (opt == 3u && opt_len >= 4u) {
            memcpy(&router, val, 4);
            router = ntohl(router);
        } else if (opt == 6u && opt_len >= 4u) {
            memcpy(&dns, val, 4);
            dns = ntohl(dns);
        }
        off += opt_len;
    }
    if (type == 2u) {
        memcpy(g_dhcp_server_mac, src_mac, 6);
        g_dhcp_server_ip = server_id;
        dhcp_send(3u, ntohl(pkt->yiaddr), server_id);
    } else if (type == 5u) {
        g_config.address = ntohl(pkt->yiaddr);
        g_config.netmask = mask != 0u ? mask : ip4(255, 255, 255, 0);
        g_config.gateway = router;
        g_config.dns = dns;
        g_config.configured = true;
        g_dhcp_running = false;
        if (g_dhcp_server_ip != 0u) {
            arp_remember(g_dhcp_server_ip, g_dhcp_server_mac);
        }
        console_printf("net: dhcp %u.%u.%u.%u gw %u.%u.%u.%u dns %u.%u.%u.%u\n", (unsigned)(g_config.address >> 24),
                       (unsigned)((g_config.address >> 16) & 0xffu), (unsigned)((g_config.address >> 8) & 0xffu),
                       (unsigned)(g_config.address & 0xffu), (unsigned)(g_config.gateway >> 24),
                       (unsigned)((g_config.gateway >> 16) & 0xffu), (unsigned)((g_config.gateway >> 8) & 0xffu),
                       (unsigned)(g_config.gateway & 0xffu), (unsigned)(g_config.dns >> 24), (unsigned)((g_config.dns >> 16) & 0xffu),
                       (unsigned)((g_config.dns >> 8) & 0xffu), (unsigned)(g_config.dns & 0xffu));
        if (g_config.gateway != 0u) {
            arp_remember(g_config.gateway, src_mac);
        }
    }
}

static struct tcp_connection* tcp_find(uint16_t local_port, uint32_t remote_ip, uint16_t remote_port) {
    for (size_t i = 0; i < MAX_TCP_CONNECTIONS; ++i) {
        if (g_tcp[i].used && g_tcp[i].local_port == local_port &&
            (remote_ip == 0u || (g_tcp[i].remote_ip == remote_ip && g_tcp[i].remote_port == remote_port))) {
            return &g_tcp[i];
        }
    }
    return NULL;
}

static bool tcp_send_segment(struct tcp_connection* conn, uint8_t flags, const void* data, size_t len) {
    uint8_t packet[1500];
    if (conn == NULL || len + sizeof(struct tcp_hdr) > sizeof(packet)) {
        return false;
    }
    struct tcp_hdr* tcp = (struct tcp_hdr*)packet;
    memset(tcp, 0, sizeof(*tcp));
    tcp->src_port = htons(conn->local_port);
    tcp->dst_port = htons(conn->remote_port);
    tcp->seq = htonl(conn->seq);
    tcp->ack = htonl(conn->ack);
    tcp->data_off = (uint8_t)(5u << 4);
    tcp->flags = flags;
    tcp->window = htons(32768u);
    if (len != 0u) {
        memcpy(packet + sizeof(*tcp), data, len);
    }
    tcp->checksum = htons(transport_checksum(g_config.address, conn->remote_ip, IP_PROTO_TCP, packet, sizeof(*tcp) + len));
    return send_ipv4(conn->remote_ip, IP_PROTO_TCP, packet, sizeof(*tcp) + len);
}

int net_tcp_open(uint16_t local_port, uint32_t dst_ip, uint16_t dst_port) {
    if (local_port == 0u) {
        local_port = net_ephemeral_port();
    }
    for (size_t i = 0; i < MAX_TCP_CONNECTIONS; ++i) {
        if (!g_tcp[i].used) {
            struct tcp_connection* conn = &g_tcp[i];
            memset(conn, 0, sizeof(*conn));
            conn->used = true;
            conn->state = TCP_SYN_SENT;
            conn->local_port = local_port;
            conn->remote_ip = dst_ip;
            conn->remote_port = dst_port;
            conn->seq = g_tcp_seed += 0x1000u;
            conn->remote_window = 32768u;
            (void)resolve_mac(dst_ip, conn->remote_mac);
            if (!tcp_send_segment(conn, TCP_SYN, NULL, 0u)) {
                memset(conn, 0, sizeof(*conn));
                return -1;
            }
            conn->seq++;
            return (int)local_port;
        }
    }
    return -1;
}

bool net_tcp_connected(uint16_t local_port) {
    struct tcp_connection* conn = tcp_find(local_port, 0u, 0u);
    return conn != NULL && conn->state == TCP_ESTABLISHED;
}

bool net_tcp_closed(uint16_t local_port) {
    struct tcp_connection* conn = tcp_find(local_port, 0u, 0u);
    return conn == NULL || conn->state == TCP_CLOSED;
}

int net_tcp_send(uint16_t local_port, const void* data, size_t len) {
    struct tcp_connection* conn = tcp_find(local_port, 0u, 0u);
    if (conn == NULL || conn->state != TCP_ESTABLISHED) {
        return -1;
    }
    size_t n = len;
    if (n > 1200u) {
        n = 1200u;
    }
    if (!tcp_send_segment(conn, TCP_ACK | TCP_PSH, data, n)) {
        return -1;
    }
    conn->seq += (uint32_t)n;
    return (int)n;
}

int net_tcp_recv(uint16_t local_port, void* data, size_t len) {
    struct tcp_connection* conn = tcp_find(local_port, 0u, 0u);
    if (conn == NULL) {
        return -1;
    }
    if (conn->read_size == 0u) {
        return conn->state == TCP_CLOSE_WAIT || conn->state == TCP_CLOSED ? 0 : -1;
    }
    size_t n = len < conn->read_size ? len : conn->read_size;
    size_t first = n;
    if (first > TCP_BUFFER_CAPACITY - conn->read_off) {
        first = TCP_BUFFER_CAPACITY - conn->read_off;
    }
    memcpy(data, &conn->read_buf[conn->read_off], first);
    if (n > first) {
        memcpy((uint8_t*)data + first, conn->read_buf, n - first);
    }
    conn->read_off = (conn->read_off + n) % TCP_BUFFER_CAPACITY;
    conn->read_size -= n;
    return (int)n;
}

size_t net_tcp_pending(uint16_t local_port) {
    struct tcp_connection* conn = tcp_find(local_port, 0u, 0u);
    return conn != NULL ? conn->read_size : 0u;
}

void net_tcp_close(uint16_t local_port) {
    struct tcp_connection* conn = tcp_find(local_port, 0u, 0u);
    if (conn == NULL) {
        return;
    }
    if (conn->state == TCP_ESTABLISHED) {
        (void)tcp_send_segment(conn, TCP_FIN | TCP_ACK, NULL, 0u);
        conn->seq++;
        conn->state = TCP_LAST_ACK;
    } else {
        memset(conn, 0, sizeof(*conn));
    }
}

static void tcp_buffer_data(struct tcp_connection* conn, const void* data, size_t len) {
    size_t avail = TCP_BUFFER_CAPACITY - conn->read_size;
    if (len > avail) {
        len = avail;
    }
    size_t write_off = (conn->read_off + conn->read_size) % TCP_BUFFER_CAPACITY;
    size_t first = len;
    if (first > TCP_BUFFER_CAPACITY - write_off) {
        first = TCP_BUFFER_CAPACITY - write_off;
    }
    memcpy(&conn->read_buf[write_off], data, first);
    if (len > first) {
        memcpy(conn->read_buf, (const uint8_t*)data + first, len - first);
    }
    conn->read_size += len;
}

static void handle_tcp(uint32_t src_ip, const uint8_t src_mac[6], const void* data, size_t len) {
    if (len < sizeof(struct tcp_hdr)) {
        return;
    }
    const struct tcp_hdr* tcp = (const struct tcp_hdr*)data;
    size_t hdr_len = (size_t)(tcp->data_off >> 4) * 4u;
    if (hdr_len < sizeof(*tcp) || hdr_len > len) {
        return;
    }
    uint16_t local_port = ntohs(tcp->dst_port);
    uint16_t remote_port = ntohs(tcp->src_port);
    struct tcp_connection* conn = tcp_find(local_port, src_ip, remote_port);
    if (conn == NULL) {
        return;
    }
    arp_remember(src_ip, src_mac);
    uint32_t seq = ntohl(tcp->seq);
    uint32_t ack = ntohl(tcp->ack);
    size_t payload_len = len - hdr_len;
    const uint8_t* payload = (const uint8_t*)data + hdr_len;
    if ((tcp->flags & TCP_RST) != 0u) {
        conn->state = TCP_CLOSED;
        return;
    }
    if (conn->state == TCP_SYN_SENT && (tcp->flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK) && ack == conn->seq) {
        conn->ack = seq + 1u;
        conn->state = TCP_ESTABLISHED;
        memcpy(conn->remote_mac, src_mac, 6);
        (void)tcp_send_segment(conn, TCP_ACK, NULL, 0u);
        return;
    }
    if (conn->state == TCP_LAST_ACK && (tcp->flags & TCP_ACK) != 0u) {
        memset(conn, 0, sizeof(*conn));
        return;
    }
    if (conn->state != TCP_ESTABLISHED && conn->state != TCP_CLOSE_WAIT) {
        return;
    }
    if (payload_len != 0u && seq == conn->ack) {
        tcp_buffer_data(conn, payload, payload_len);
        conn->ack += (uint32_t)payload_len;
        (void)tcp_send_segment(conn, TCP_ACK, NULL, 0u);
    }
    if ((tcp->flags & TCP_FIN) != 0u) {
        conn->ack = seq + (uint32_t)payload_len + 1u;
        conn->state = TCP_CLOSE_WAIT;
        (void)tcp_send_segment(conn, TCP_ACK, NULL, 0u);
    }
}

static void handle_udp(uint32_t src_ip, const uint8_t src_mac[6], const void* data, size_t len) {
    if (len < sizeof(struct udp_hdr)) {
        return;
    }
    const struct udp_hdr* udp = (const struct udp_hdr*)data;
    uint16_t udp_len = ntohs(udp->len);
    if (udp_len < sizeof(*udp) || udp_len > len) {
        return;
    }
    uint16_t src_port = ntohs(udp->src_port);
    uint16_t dst_port = ntohs(udp->dst_port);
    const uint8_t* payload = (const uint8_t*)data + sizeof(*udp);
    size_t payload_len = udp_len - sizeof(*udp);
    arp_remember(src_ip, src_mac);
    if (dst_port == DHCP_CLIENT_PORT) {
        handle_dhcp(src_mac, src_ip, payload, payload_len);
    }
    udp_deliver(src_ip, src_port, dst_port, payload, payload_len);
}

static void handle_icmp(uint32_t src_ip, const void* data, size_t len) {
    for (size_t i = 0; i < MAX_RAW_ICMP_SOCKETS; ++i) {
        struct raw_icmp_socket* sock = &g_raw_icmp[i];
        if (!sock->used || sock->count >= RAW_ICMP_QUEUE_PACKETS) {
            continue;
        }
        uint16_t idx = (uint16_t)((sock->head + sock->count) % RAW_ICMP_QUEUE_PACKETS);
        struct raw_icmp_packet* packet = &sock->packets[idx];
        packet->used = true;
        packet->src_ip = src_ip;
        packet->len = len + sizeof(struct ipv4_hdr);
        if (packet->len > RAW_ICMP_PACKET_CAPACITY) {
            packet->len = RAW_ICMP_PACKET_CAPACITY;
        }

        struct ipv4_hdr* ip = (struct ipv4_hdr*)packet->data;
        memset(ip, 0, sizeof(*ip));
        ip->ver_ihl = 0x45u;
        ip->total_len = htons((uint16_t)(sizeof(*ip) + len));
        ip->ttl = 64u;
        ip->proto = IP_PROTO_ICMP;
        ip->src = htonl(src_ip);
        ip->dst = htonl(g_config.address);
        ip->checksum = htons(checksum(ip, sizeof(*ip)));
        size_t copy = packet->len - sizeof(*ip);
        memcpy(packet->data + sizeof(*ip), data, copy);
        sock->count++;
    }

    if (len < sizeof(struct icmp_hdr)) {
        return;
    }
    const struct icmp_hdr* icmp = (const struct icmp_hdr*)data;
    if (icmp->type != 8u) {
        return;
    }
    uint8_t reply[1500];
    if (len > sizeof(reply)) {
        return;
    }
    memcpy(reply, data, len);
    struct icmp_hdr* out = (struct icmp_hdr*)reply;
    out->type = 0u;
    out->checksum = 0u;
    out->checksum = htons(checksum(reply, len));
    (void)send_ipv4(src_ip, IP_PROTO_ICMP, reply, len);
}

static void handle_ipv4(const struct eth_hdr* eth, const void* data, size_t len) {
    if (len < sizeof(struct ipv4_hdr)) {
        return;
    }
    const struct ipv4_hdr* ip = (const struct ipv4_hdr*)data;
    size_t ihl = (size_t)(ip->ver_ihl & 0x0Fu) * 4u;
    if ((ip->ver_ihl >> 4) != 4u || ihl < sizeof(*ip) || ihl > len) {
        return;
    }
    uint16_t total_len = ntohs(ip->total_len);
    if (total_len < ihl || total_len > len) {
        return;
    }
    uint32_t src_ip = ntohl(ip->src);
    uint32_t dst_ip = ntohl(ip->dst);
    if (g_config.configured && dst_ip != g_config.address && dst_ip != 0xFFFFFFFFu) {
        return;
    }
    const uint8_t* payload = (const uint8_t*)data + ihl;
    size_t payload_len = total_len - ihl;
    if (ip->proto == IP_PROTO_UDP) {
        handle_udp(src_ip, eth->src, payload, payload_len);
    } else if (ip->proto == IP_PROTO_TCP) {
        handle_tcp(src_ip, eth->src, payload, payload_len);
    } else if (ip->proto == IP_PROTO_ICMP && g_config.configured) {
        handle_icmp(src_ip, payload, payload_len);
    }
}

static void handle_arp(const void* data, size_t len) {
    if (len < sizeof(struct arp_packet)) {
        return;
    }
    const struct arp_packet* arp = (const struct arp_packet*)data;
    if (ntohs(arp->htype) != 1u || ntohs(arp->ptype) != ETH_TYPE_IPV4 || arp->hlen != 6u || arp->plen != 4u) {
        return;
    }
    uint32_t spa = ntohl(arp->spa);
    uint32_t tpa = ntohl(arp->tpa);
    arp_remember(spa, arp->sha);
    if (g_config.configured && ntohs(arp->oper) == 1u && tpa == g_config.address) {
        send_arp_reply(arp->sha, spa);
    }
}

void net_receive_ethernet(const void* frame, size_t len) {
    if (len < sizeof(struct eth_hdr)) {
        return;
    }
    const struct eth_hdr* eth = (const struct eth_hdr*)frame;
    uint16_t type = ntohs(eth->type);
    const uint8_t* payload = (const uint8_t*)frame + sizeof(*eth);
    size_t payload_len = len - sizeof(*eth);
    if (type == ETH_TYPE_ARP) {
        handle_arp(payload, payload_len);
    } else if (type == ETH_TYPE_IPV4) {
        handle_ipv4(eth, payload, payload_len);
    }
}

void net_poll(void) {
    virtio_net_poll();
}

static void dhcp_start(void) {
    g_dhcp_running = true;
    (void)net_udp_bind(DHCP_CLIENT_PORT);
    dhcp_send(1u, 0u, 0u);
    for (uint32_t spins = 0; spins < 2000000u && !g_config.configured; ++spins) {
        net_poll();
        if ((spins % 500000u) == 499999u) {
            dhcp_send(1u, 0u, 0u);
        }
        __asm__ volatile("pause" : : : "memory");
    }
    if (!g_config.configured) {
        console_write("net: dhcp did not complete\n");
    }
}

void net_init(const uint8_t mac[NET_ETH_ADDR_LEN], net_link_send_fn send_fn) {
    memset(&g_config, 0, sizeof(g_config));
    memset(g_arp, 0, sizeof(g_arp));
    memset(g_udp, 0, sizeof(g_udp));
    memset(g_tcp, 0, sizeof(g_tcp));
    memset(g_raw_icmp, 0, sizeof(g_raw_icmp));
    memcpy(g_config.mac, mac, NET_ETH_ADDR_LEN);
    g_send = send_fn;
    dhcp_start();
}

const struct net_ipv4_config* net_config(void) {
    return &g_config;
}

int net_icmp_open(void) {
    for (size_t i = 0; i < MAX_RAW_ICMP_SOCKETS; ++i) {
        if (!g_raw_icmp[i].used) {
            memset(&g_raw_icmp[i], 0, sizeof(g_raw_icmp[i]));
            g_raw_icmp[i].used = true;
            return (int)i;
        }
    }
    return -1;
}

int net_icmp_send(uint32_t dst_ip, const void* data, size_t len) {
    return send_ipv4(dst_ip, IP_PROTO_ICMP, data, len) ? (int)len : -1;
}

int net_icmp_recv(int raw_id, void* data, size_t len, uint32_t* src_ip) {
    if (raw_id < 0 || raw_id >= MAX_RAW_ICMP_SOCKETS || !g_raw_icmp[raw_id].used || g_raw_icmp[raw_id].count == 0u) {
        return -1;
    }
    struct raw_icmp_socket* sock = &g_raw_icmp[raw_id];
    struct raw_icmp_packet* packet = &sock->packets[sock->head];
    size_t n = len < packet->len ? len : packet->len;
    memcpy(data, packet->data, n);
    if (src_ip != NULL) {
        *src_ip = packet->src_ip;
    }
    memset(packet, 0, sizeof(*packet));
    sock->head = (uint16_t)((sock->head + 1u) % RAW_ICMP_QUEUE_PACKETS);
    sock->count--;
    return (int)n;
}

size_t net_icmp_pending(int raw_id) {
    if (raw_id < 0 || raw_id >= MAX_RAW_ICMP_SOCKETS || !g_raw_icmp[raw_id].used || g_raw_icmp[raw_id].count == 0u) {
        return 0u;
    }
    return g_raw_icmp[raw_id].packets[g_raw_icmp[raw_id].head].len;
}

void net_icmp_close(int raw_id) {
    if (raw_id < 0 || raw_id >= MAX_RAW_ICMP_SOCKETS) {
        return;
    }
    memset(&g_raw_icmp[raw_id], 0, sizeof(g_raw_icmp[raw_id]));
}
