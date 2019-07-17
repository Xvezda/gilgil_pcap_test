#include <cstdio>
#include <cstdlib>

#include <unistd.h>


using std::printf;

int main(int argc, char **argv) {
	if (argc < 2) {
		printf("Usage: %s [interface] "
			"[-f packet_dump_file]\n", argv[0]);

		return 1;
	}
	printf("Test\n");

	return EXIT_SUCCESS;
}

