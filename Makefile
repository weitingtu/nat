CC = g++
CFLAG = -O2 -lpthread -std=c++11
ifeq ($(MODE),rd)
	CFLAG:=$(filter-out -O2, $(CFLAG))
    CFLAG += -g3 -gdwarf-4 -ggdb3 -DDEBUG
endif

all:
	$(CC) $(CFLAG) -o nftest nftest.c checksum.c checksum.h net_print.c net_print.h -lnfnetlink -lnetfilter_queue

clean:
	@rm -f nftest
