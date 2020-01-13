CPP=g++
CPPFLAGS=-std=c++14
#CPPFLAGS=-g -DDEBUG
LDLIBS=-lpcap

TARGET=pcap_test


all: $(TARGET)

clean:
	rm -f *.o
	rm -f $(TARGET)
