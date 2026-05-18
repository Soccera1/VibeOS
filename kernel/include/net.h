#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NET_ETH_ADDR_LEN 6u
#define NET_IPV4_ADDR_LEN 4u

struct net_ipv4_config {
    uint8_t mac[NET_ETH_ADDR_LEN];
    uint32_t address;
    uint32_t netmask;
    uint32_t gateway;
    uint32_t dns;
    bool configured;
};

typedef bool (*net_link_send_fn)(const void* frame, size_t len);

void net_init(const uint8_t mac[NET_ETH_ADDR_LEN], net_link_send_fn send_fn);
void net_poll(void);
void net_receive_ethernet(const void* frame, size_t len);
const struct net_ipv4_config* net_config(void);

int net_udp_bind(uint16_t requested_port);
int net_udp_send(uint16_t local_port, uint32_t dst_ip, uint16_t dst_port, const void* data, size_t len);
int net_udp_recv(uint16_t local_port, void* data, size_t len, uint32_t* src_ip, uint16_t* src_port);
size_t net_udp_pending(uint16_t local_port);

uint16_t net_ephemeral_port(void);
int net_tcp_open(uint16_t local_port, uint32_t dst_ip, uint16_t dst_port);
int net_tcp_send(uint16_t local_port, const void* data, size_t len);
int net_tcp_recv(uint16_t local_port, void* data, size_t len);
bool net_tcp_connected(uint16_t local_port);
bool net_tcp_closed(uint16_t local_port);
size_t net_tcp_pending(uint16_t local_port);
void net_tcp_close(uint16_t local_port);

int net_icmp_open(void);
int net_icmp_send(uint32_t dst_ip, const void* data, size_t len);
int net_icmp_recv(int raw_id, void* data, size_t len, uint32_t* src_ip);
size_t net_icmp_pending(int raw_id);
void net_icmp_close(int raw_id);
