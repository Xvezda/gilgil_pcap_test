CPP=g++
CPPFLAGS=-g

TARGET=pcap_test


all: $(TARGET)

clean:
	rm -f *.o
	rm -f $(TARGET)
