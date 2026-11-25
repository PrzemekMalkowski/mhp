CFLAGS ?= -O2 -g
CFLAGS += -fPIC -fno-omit-frame-pointer -Wall -Wextra -std=gnu11

../bin/libmhp.so: mhp_preload.c mhp_ring.h
	mkdir -p ../bin
	$(CC) $(CFLAGS) -shared -Wl,-Bsymbolic-functions -o $@ mhp_preload.c -lm -lpthread -ldl

../bin/mhp_selftest: selftest.c
	$(CC) -O1 -g -fno-omit-frame-pointer -pthread -o $@ selftest.c

clean:
	rm -f ../bin/libmhp.so ../bin/mhp_selftest
