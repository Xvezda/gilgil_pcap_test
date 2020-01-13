CPP = g++
CPPFLAGS = -std=c++14
#CPPFLAGS = -std=c++14 -O0 -g -DDEBUG
LDLIBS = -lpcap

SRC_FILE = pcap_test.cpp
TARGET = $(patsubst %.cpp, %, $(SRC_FILE))


all: $(TARGET)

clean:
	rm -f *.o
	rm -f $(TARGET)
