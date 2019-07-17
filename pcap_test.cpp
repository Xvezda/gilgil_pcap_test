/*
 * Copyright (c) 2019 Xvezda <https://xvezda.com>
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdint.h>

#include <pcap.h>

#include <unistd.h>
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

struct ip_header {
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
	uint8_t *options;  // Up to 40 bytes
	// TODO: Here comes tcp/udp header
};
typedef struct ip_header ip_t;

struct ethernet_frame {
	uint8_t smac[6];
	uint8_t dmac[6];
	uint8_t type[2];
	ip_t data;
};
typedef struct ethernet_frame eth_t;

eth_t wrap_packet(const u_char *packet);

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
			eth_t ethernet = wrap_packet(packet);
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


eth_t wrap_packet(const u_char *packet) {
	eth_t ret;
	u_char *cur = const_cast<u_char*>(packet);

	PUSH(cur, ret.smac, sizeof ret.smac);
	PUSH(cur, ret.dmac, sizeof ret.dmac);
	PUSH(cur, ret.type, sizeof ret.type);

	uint8_t tmp8_t;
	PUSH(cur, &tmp8_t, sizeof tmp8_t);
	ret.data.version = tmp8_t & 0xf0;
	ret.data.header_length = tmp8_t & 0x0f;

	PUSH(cur, &ret.data.type, sizeof ret.data.type);
	PUSH(cur, &ret.data.packet_length, sizeof ret.data.packet_length);
	PUSH(cur, &ret.data.identifier, sizeof ret.data.identifier);

	uint16_t tmp16_t;
	PUSH(cur, &tmp16_t, sizeof tmp16_t);
	ret.data.flags = tmp16_t & 0xe000;
	ret.data.fragment_offset = tmp16_t & 0x1fff;
	
	PUSH(cur, &ret.data.ttl, sizeof ret.data.ttl);
	PUSH(cur, &ret.data.protocol_type, sizeof ret.data.protocol_type);
	PUSH(cur, &ret.data.checksum, sizeof ret.data.checksum);

	PUSH(cur, ret.data.sip, sizeof ret.data.sip);
	PUSH(cur, ret.data.dip, sizeof ret.data.dip);

#ifdef DEBUG
	printf("s-mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
		ret.smac[0], ret.smac[1], ret.smac[2],
		ret.smac[3], ret.smac[4], ret.smac[5]);
	printf("d-mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
		ret.dmac[0], ret.dmac[1], ret.dmac[2],
		ret.dmac[3], ret.dmac[4], ret.dmac[5]);
	printf("s-ip: %u.%u.%u.%u\n",
		ret.data.sip[0], ret.data.sip[1],
		ret.data.sip[2], ret.data.sip[3]);
	printf("d-ip: %u.%u.%u.%u\n",
		ret.data.dip[0], ret.data.dip[1],
		ret.data.dip[2], ret.data.dip[3]);
	printf("protocol: %s\n", 
		(ret.data.protocol_type == TCP_NUMBER) ? "TCP" : "UDP");
#endif
	return ret;
}

