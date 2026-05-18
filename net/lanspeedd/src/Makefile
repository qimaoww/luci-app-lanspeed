CC ?= cc
CFLAGS ?= -Os -Wall -Wextra
LDFLAGS ?=
LIBS ?= -lubox -lubus -luci -lblobmsg_json -ljson-c -lmnl
CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -Wall -Wextra -target bpf
LANSPEED_WITH_BPF ?= 0

BPF_IMPL_OBJ := lanspeed_bpf_stub.o
ifeq ($(LANSPEED_WITH_BPF),1)
LIBS += -lbpf
BPF_IMPL_OBJ := lanspeed_bpf.o
endif

OBJS := lanspeedd.o $(BPF_IMPL_OBJ)

all: lanspeedd

lanspeedd: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c lanspeed_bpf.h
	$(CC) $(CFLAGS) -c -o $@ $<

bpf: lanspeed_tc.o

lanspeed_tc.o: lanspeed_tc.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c -o $@ $<

clean:
	rm -f lanspeedd $(OBJS) lanspeed_bpf.o lanspeed_bpf_stub.o lanspeed_tc.o

.PHONY: all bpf clean
