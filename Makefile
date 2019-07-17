CPP=g++
CPPFLAGS=-g -DDEBUG
LDLIBS=-lpcap

TARGET=pcap_test


all: $(TARGET)

clean:
	rm -f *.o
	rm -f $(TARGET)
