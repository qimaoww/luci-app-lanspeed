CC ?= cc
CFLAGS ?= -Os -Wall -Wextra
LDFLAGS ?=
LIBS ?= -lubox -lubus -luci -lblobmsg_json -ljson-c -lbpf
CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -Wall -Wextra -target bpf

OBJS := lanspeedd.o lanspeed_bpf.o

all: lanspeedd

lanspeedd: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c lanspeed_bpf.h
	$(CC) $(CFLAGS) -c -o $@ $<

bpf: lanspeed_tc.o

lanspeed_tc.o: lanspeed_tc.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c -o $@ $<

clean:
	rm -f lanspeedd $(OBJS) lanspeed_tc.o

.PHONY: all bpf clean
