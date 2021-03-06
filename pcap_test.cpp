/*
 * Copyright (c) 2019 Xvezda <https://xvezda.com>
 */
#include "pcap_test.h"

using std::printf;
using std::strlen;
using std::memcpy;

#define PUSH(cursor, target, size) 				\
	do { 							\
		memcpy(target, cursor, size);			\
		(cursor) += (size);				\
	} while (0);


int main(int argc, char **argv) {
	if (argc != 2) {
		printf("Usage: %s [interface]\n", argv[0]);

		return EXIT_FAILURE;
	}
	char errbuf[PCAP_ERRBUF_SIZE];
	char *device = nullptr;
	pcap_t *handle = nullptr;

	device = argv[1];
	handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "Couldn't open device %s: %s\n",
			device, errbuf);
		return EXIT_FAILURE;
	}
	for (;;) {
		struct pcap_pkthdr *header;
		const u_char *raw_packet;

		int res = pcap_next_ex(handle, &header, &raw_packet);
		if (!res) continue;
		if (res == -1 || res == -2) break;

		eth_t ethernet = wrap_packet_eth(raw_packet);
		analyze_packet(ethernet);
	}
	pcap_close(handle);

	return EXIT_SUCCESS;
}


eth_t wrap_packet_eth(const u_char *raw_packet) {
	eth_t ret;
	u_char *cur = const_cast<u_char*>(raw_packet);

	PUSH(cur, ret.smac, sizeof ret.smac);
	PUSH(cur, ret.dmac, sizeof ret.dmac);
	PUSH(cur, &ret.type, sizeof ret.type);
	ret.type = ntohs(ret.type);

	// If type is IP (IPv4)
	if (ret.type == 0x0800) {
		ret.data = wrap_packet_ip(cur);
	}
	return ret;
}


ip_t wrap_packet_ip(const u_char *raw_packet) {
	ip_t ret;
	u_char *cur = const_cast<u_char*>(raw_packet);

	uint8_t tmp_8;
	PUSH(cur, &tmp_8, sizeof tmp_8);
	ret.version = (tmp_8 & 0xf0) >> 4;
	ret.header_length = (tmp_8 & 0x0f) * 4;

	PUSH(cur, &ret.type, sizeof ret.type);
	PUSH(cur, &ret.packet_length, sizeof ret.packet_length);
	PUSH(cur, &ret.identifier, sizeof ret.identifier);
	ret.packet_length = ntohs(ret.packet_length);

	uint16_t tmp_16;
	PUSH(cur, &tmp_16, sizeof tmp_16);
	ret.flags = tmp_16 & 0xe000;
	ret.fragment_offset = tmp_16 & 0x1fff;
	
	PUSH(cur, &ret.ttl, sizeof ret.ttl);
	PUSH(cur, &ret.protocol_type, sizeof ret.protocol_type);
	PUSH(cur, &ret.checksum, sizeof ret.checksum);

	PUSH(cur, ret.sip, sizeof ret.sip);
	PUSH(cur, ret.dip, sizeof ret.dip);

	// Check protocol type
	switch (ret.protocol_type) {
	case TCP_NUMBER:  // Is it tcp?
		ret.tcp = wrap_packet_tcp(cur,
				ret.packet_length
				- (IP_HEADER_SIZE+TCP_HEADER_SIZE));
		break;
	case UDP_NUMBER:
		break;
	default:
		break;
	}
	return ret;
}


tcp_t wrap_packet_tcp(const u_char *raw_packet, size_t len) {
	tcp_t ret;
	u_char *cur = const_cast<u_char*>(raw_packet);

	PUSH(cur, &ret.sp, sizeof ret.sp);
	PUSH(cur, &ret.dp, sizeof ret.dp);
	ret.sp = ntohs(ret.sp);
	ret.dp = ntohs(ret.dp);

	PUSH(cur, &ret.seq, sizeof ret.seq);
	PUSH(cur, &ret.ack, sizeof ret.ack);
	
	uint16_t tmp_16;
	PUSH(cur, &tmp_16, sizeof tmp_16);
	ret.offset = ntohs(tmp_16) >> 12;
	
	PUSH(cur, &ret.window_size, sizeof ret.window_size);
	PUSH(cur, &ret.checksum, sizeof ret.checksum);
	PUSH(cur, &ret.urgent_pointer, sizeof ret.urgent_pointer);
	
	ret.tcp_size = len;
	if (!ret.tcp_size) {
		ret.data = nullptr;
	} else {
		int i;
		char buffer[0x100];
		for (i = 0;
			i < len && i < sizeof buffer - 1; ++cur, ++i) {
			buffer[i] = *cur;
		}
		ret.data = new uint8_t[i];
		memcpy(ret.data, buffer, i);
	}
	return ret;
}


udp_t wrap_packet_udp(const u_char *raw_packet) {
	udp_t ret;
	u_char *cur = const_cast<u_char*>(raw_packet);
	return ret;
}


void analyze_packet(eth_t packet) {
	show_mac(packet);
	show_ip(packet.data);
	switch (packet.data.protocol_type) {
	case TCP_NUMBER:
		show_tcp(packet.data.tcp);
		break;
	case UDP_NUMBER:
		break;
	default:
		break;
	}
	printf("\n");
}

void show_mac(eth_t packet) {
	int i;
	printf("eth.smac:\t");
	for (i = 0; i < sizeof packet.smac; ++i) {
		printf("%02x%c", packet.smac[i],
			(i != sizeof packet.smac-1) ? ':' : '\n');
	}
	printf("eth.dmac:\t");
	for (i = 0; i < sizeof packet.dmac; ++i) {
		printf("%02x%c", packet.dmac[i],
			(i != sizeof packet.dmac-1) ? ':' : '\n');
	}
}

void show_ip(ip_t packet) {
	int i;
	printf("ip.sip:\t\t");
	for (i = 0; i < sizeof packet.sip; ++i) {
		printf("%u%c", packet.sip[i],
			(i != sizeof packet.sip-1) ? '.' : '\n');
	}
	printf("ip.dip:\t\t");
	for (i = 0; i < sizeof packet.dip; ++i) {
		printf("%u%c", packet.dip[i],
			(i != sizeof packet.dip-1) ? '.' : '\n');
	}
}

void show_tcp(tcp_t packet) {
	int i;

	printf("tcp.sport:\t");
	printf("%u\n", packet.sp);
	printf("tcp.dport:\t");
	printf("%u\n", packet.dp);
	if (packet.tcp_size) {
		printf("data:\t\t");
		for (i = 0;
			i < packet.tcp_size && i < TCP_LEN_MAX; ++i) {
			printf("%02x ", packet.data[i]);
		}
		printf("\n");
	}
}

