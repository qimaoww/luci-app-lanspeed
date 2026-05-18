CC ?= cc
CFLAGS ?= -Os -Wall -Wextra
LDFLAGS ?=
LIBS ?= -lubox -lubus -luci -lblobmsg_json -ljson-c -lmnl
CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -Wall -Wextra -target bpf
LANSPEED_WITH_BPF ?= 0
PLUGIN_CFLAGS ?= $(CFLAGS) -fPIC
PLUGIN_LDFLAGS ?= $(LDFLAGS) -shared
LIBBPF_LIBS ?= -lbpf

BPF_IMPL_OBJ := lanspeed_bpf_stub.o

OBJS := lanspeedd.o $(BPF_IMPL_OBJ)

all: lanspeedd

lanspeedd: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c lanspeed_bpf.h
	$(CC) $(CFLAGS) -c -o $@ $<

bpf: lanspeed_tc.o

plugin: lanspeed_bpf_plugin.so

lanspeed_bpf_plugin.so: lanspeed_bpf.c lanspeed_bpf.h
	$(CC) $(PLUGIN_CFLAGS) -o $@ $< $(PLUGIN_LDFLAGS) $(LIBBPF_LIBS)

lanspeed_tc.o: lanspeed_tc.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c -o $@ $<

clean:
	rm -f lanspeedd $(OBJS) lanspeed_bpf.o lanspeed_bpf_stub.o lanspeed_tc.o lanspeed_bpf_plugin.so

.PHONY: all bpf plugin clean
