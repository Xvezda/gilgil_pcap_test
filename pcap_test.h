/*
 * Copyright (c) 2019 Xvezda <https://xvezda.com>
 */
#ifndef _PCAP_TEST_H__
#define _PCAP_TEST_H__

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdint.h>

#include <pcap.h>
#include <unistd.h>
#include <arpa/inet.h>

#define ETH_HEADER_SIZE 24
#define IP_HEADER_SIZE  20
#define TCP_HEADER_SIZE 20
#define TCP_LEN_MAX     10

enum ProtocolNumber {
	TCP_NUMBER = 0x06,
	UDP_NUMBER = 0x11
};

struct tcp_packet {
	uint16_t sp;
	uint16_t dp;
	uint32_t seq;
	uint32_t ack;
	unsigned offset		: 4;
	unsigned reserved	: 4;
	unsigned control_flag	: 8;
	uint16_t window_size;
	uint16_t checksum;
	uint16_t urgent_pointer;
	uint8_t *data;
	size_t tcp_size;
};
typedef struct tcp_packet tcp_t;

struct udp_packet {
	uint16_t sp;
	uint16_t dp;
	uint16_t length;
	uint16_t checksum;
	uint8_t *data;
};
typedef struct udp_packet udp_t;

struct ip_packet {
	unsigned version		: 4;
	unsigned header_length		: 4;
	uint8_t	type;
	uint16_t packet_length;
	uint16_t identifier;
	unsigned flags			: 3;
	unsigned fragment_offset	: 13;
	uint8_t ttl;
	uint8_t protocol_type;  // TCP: 0x06, UDP: 0x11
	uint16_t checksum;
	uint8_t sip[4];
	uint8_t dip[4];
	union {
		tcp_t tcp;
		udp_t udp;
	};
};
typedef struct ip_packet ip_t;

struct ethernet_frame {
	uint8_t smac[6];
	uint8_t dmac[6];
	uint16_t type;
	ip_t data;
};
typedef struct ethernet_frame eth_t;

eth_t	wrap_packet_eth(const u_char *raw_packet);
ip_t	wrap_packet_ip(const u_char *raw_packet);
tcp_t	wrap_packet_tcp(const u_char *raw_packet, size_t len);
udp_t	wrap_packet_udp(const u_char *raw_packet);
void	analyze_packet(eth_t packet);
void 	show_mac(eth_t packet);
void 	show_ip(ip_t packet);
void 	show_tcp(tcp_t packet);

#endif  /* End of _PCAP_TEST_H__ */
