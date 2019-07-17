/*
 * Copyright (c) 2019 Xvezda <https://xvezda.com>
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <pcap.h>

#include <unistd.h>
#include <linux/limits.h>


using std::printf;
using std::strlen;
using std::memcpy;

int main(int argc, char **argv) {
	if (argc < 2) {
		printf("Usage: %s [interface] "
			"[-f packet_dumpfile_path]\n", argv[0]);

		return EXIT_FAILURE;
	}
	int o = 0;
	char *filepath = nullptr;
	while ((o = getopt(argc, argv, "f:")) != -1) {
		switch (o) {
		case 'f': {
			size_t optlen = strlen(optarg);
			if (optlen > PATH_MAX) {
				printf("File path argument too long.");
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
				printf("Missing argument to "
					"packet file path.\n");
				break;
			default:
				printf("Unknown option: %c\n", o);
				break;
			}
			return EXIT_FAILURE;

			break;
		}
	}
	char *device = nullptr;
	pcap_t *handle = nullptr;

	if (filepath == nullptr) {
		printf("Device: %s\n", argv[1]);
	} else {
		printf("File Path: %s\n", filepath);
		delete filepath;
	}
	return EXIT_SUCCESS;
}

