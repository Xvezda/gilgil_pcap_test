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
	uint16_t ttl;
	uint8_t protocol_id;
	uint16_t checksum;
	uint32_t sip;
	uint32_t dip;
	uint8_t *options;
	// TODO: Here comes tcp/udp header
};
typedef struct ip_header ip_t;

struct ethernet_frame {
	uint8_t smac[6];
	uint8_t dmac[6];
	uint8_t type[2];
	ip_t data_unit;
};
typedef struct ethernet_frame eth_t;

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
		struct pcap_pkthdr header;
		const u_char *packet;
		packet = pcap_next(handle, &header);
		printf("Packet length: %d\n", header.len);
		pcap_close(handle);
	} else {
#ifdef DEBUG
		printf("File Path: %s\n", filepath);
#endif
		delete filepath;
	}
	return EXIT_SUCCESS;
}

