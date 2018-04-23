all:
	g++  -std=c++11 -o nftest nftest.c checksum.c checksum.h net_print.c net_print.h -lnfnetlink -lnetfilter_queue

clean:
	@rm -f nftest
