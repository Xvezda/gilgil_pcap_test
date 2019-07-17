/*
 * Copyright (c) 2019 Xvezda <https://xvezda.com>
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdint.h>

#include <pcap.h>

#include <unistd.h>
#include <arpa/inet.h>
#include <linux/limits.h>

#define PUSH(cursor, target, size) 				\
	do { 							\
		std::memcpy(target, cursor, size);		\
		cursor += size;					\
	} while (0);

#define TCP_NUMBER 0x06
#define UDP_NUMBER 0x11


using std::printf;
using std::strlen;
using std::memcpy;

struct tcp_packet {
	uint16_t sp;
	uint16_t dp;
	uint32_t seq;
	uint32_t ack;
	unsigned offset : 4;
	unsigned reserved : 3;
	unsigned control_flag : 9;
	/*
	uint16_t window_size;
	uint16_t checksum;
	uint16_t urgent_pointer;
	uint8_t *data;
	*/
};
typedef struct tcp_packet tcp_t;

struct udp_packet {
};
typedef struct udp_packet udp_t;

struct ip_packet {
	unsigned version : 4;
	unsigned header_length : 4;
	uint8_t type;
	uint16_t packet_length;
	uint16_t identifier;
	unsigned flags : 3;
	unsigned fragment_offset : 13;
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
	uint8_t type[2];
	ip_t data;
};
typedef struct ethernet_frame eth_t;

eth_t	wrap_packet_eth(const u_char *packet);
ip_t	wrap_packet_ip(const u_char *packet);
tcp_t	wrap_packet_tcp(const u_char *packet);
udp_t	wrap_packet_udp(const u_char *packet);

int main(int argc, char **argv) {
	if (argc < 2) {
		printf("Usage: %s [interface] "
			"[-f packet_dumpfile_path]\n", argv[0]);

		return EXIT_FAILURE;
	}

	int o = 0;

	char *filepath = nullptr;
	char errbuf[PCAP_ERRBUF_SIZE];

	while ((o = getopt(argc, argv, "f:")) != -1) {
		switch (o) {
		case 'f': {
			size_t optlen = strlen(optarg);
			if (optlen > PATH_MAX) {
				fprintf(stderr, "File path argument too long.");
				return EXIT_FAILURE;
			}
			filepath = new char[optlen];
			memcpy(filepath, optarg, optlen);
			break;
		}
		case '?':
		default:
			switch (optopt) {
			case 'f':
				fprintf(stderr, "Missing argument to "
						"packet file path.\n");
				break;
			default:
				fprintf(stderr, "Unknown option: %c\n", o);
				break;
			}
			return EXIT_FAILURE;

			break;
		}
	}
	char *device = nullptr;
	pcap_t *handle = nullptr;

	if (filepath == nullptr) {
		device = argv[1];
#ifdef DEBUG
		printf("Device: %s\n", device);
#endif
		handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
		if (handle == nullptr) {
			fprintf(stderr, "Couldn't open device %s: %s\n",
				device, errbuf);
			return EXIT_FAILURE;
		}
		for (;;) {
			struct pcap_pkthdr *header;
			const u_char *packet;

			int res = pcap_next_ex(handle, &header, &packet);
			if (!res) continue;
			if (res == -1 || res == -2) break;
#ifdef DEBUG
			printf("Packet length: %d\n", header->caplen);
			eth_t ethernet = wrap_packet_eth(packet);
#endif
		}
		pcap_close(handle);
	} else {
#ifdef DEBUG
		printf("File Path: %s\n", filepath);
#endif
		delete filepath;
	}
	return EXIT_SUCCESS;
}


eth_t wrap_packet_eth(const u_char *packet) {
	eth_t ret;
	u_char *cur = const_cast<u_char*>(packet);

	PUSH(cur, ret.smac, sizeof ret.smac);
	PUSH(cur, ret.dmac, sizeof ret.dmac);
	PUSH(cur, ret.type, sizeof ret.type);
	
	ret.data = wrap_packet_ip(cur);
#ifdef DEBUG
	printf("s-mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
		ret.smac[0], ret.smac[1], ret.smac[2],
		ret.smac[3], ret.smac[4], ret.smac[5]);
	printf("d-mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
		ret.dmac[0], ret.dmac[1], ret.dmac[2],
		ret.dmac[3], ret.dmac[4], ret.dmac[5]);
#endif
	return ret;
}


ip_t wrap_packet_ip(const u_char *packet) {
	ip_t ret;
	u_char *cur = const_cast<u_char*>(packet);

	uint8_t tmp_8;
	PUSH(cur, &tmp_8, sizeof tmp_8);
	ret.version = tmp_8 & 0xf0;
	ret.header_length = tmp_8 & 0x0f;

	PUSH(cur, &ret.type, sizeof ret.type);
	PUSH(cur, &ret.packet_length, sizeof ret.packet_length);
	PUSH(cur, &ret.identifier, sizeof ret.identifier);

	uint16_t tmp_16;
	PUSH(cur, &tmp_16, sizeof tmp_16);
	ret.flags = tmp_16 & 0xe000;
	ret.fragment_offset = tmp_16 & 0x1fff;
	
	PUSH(cur, &ret.ttl, sizeof ret.ttl);
	PUSH(cur, &ret.protocol_type, sizeof ret.protocol_type);
	PUSH(cur, &ret.checksum, sizeof ret.checksum);

	PUSH(cur, ret.sip, sizeof ret.sip);
	PUSH(cur, ret.dip, sizeof ret.dip);

#ifdef DEBUG
	printf("s-ip: %u.%u.%u.%u\n",
		ret.sip[0], ret.sip[1],
		ret.sip[2], ret.sip[3]);
	printf("d-ip: %u.%u.%u.%u\n",
		ret.dip[0], ret.dip[1],
		ret.dip[2], ret.dip[3]);
#endif
	switch (ret.protocol_type) {
	case TCP_NUMBER:
		ret.tcp = wrap_packet_tcp(cur);
		break;
	case UDP_NUMBER:
		break;
	default:
		break;
	}

	return ret;
}


tcp_t wrap_packet_tcp(const u_char *packet) {
	tcp_t ret;
	u_char *cur = const_cast<u_char*>(packet);

	PUSH(cur, &ret.sp, sizeof ret.sp);
	PUSH(cur, &ret.dp, sizeof ret.dp);

#ifdef DEBUG
	printf("s-port: %u\n", ntohs(ret.sp));
	printf("d-port: %u\n", ntohs(ret.dp));
#endif
	return ret;
}


udp_t wrap_packet_udp(const u_char *packet) {
	udp_t ret;
	u_char *cur = const_cast<u_char*>(packet);

	return ret;
}

