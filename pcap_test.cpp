/*
 * Copyright (c) 2019 Xvezda <https://xvezda.com>
 */
#include <cstdio>
#include <cstdlib>

#include <unistd.h>


using std::printf;

int main(int argc, char **argv) {
	if (argc < 2) {
		printf("Usage: %s [interface] "
			"[-f packet_dumpfile_path]\n", argv[0]);

		return 1;
	}
	int o;
	while ((o = getopt(argc, argv, "f:")) != -1) {
		switch (o) {
		case 'f':
			break;
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
			return 1;

			break;
		}
	}
	printf("Test: %s\n", argv[1]);

	return EXIT_SUCCESS;
}

