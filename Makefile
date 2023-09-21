ifeq (,$(INSTALL))
INSTALL = install
endif

ifeq ($(DESTDIR)$(bindir),)
bindir = /bin
endif

bindir := $(DESTDIR)$(bindir)

all: ipxgw

ipxgw: ipxgw.o
	g++ -Wall ipxgw.o `pkg-config --libs SDL_net` -lpcap -o ipxgw

ipxgw.o: ipxgw.cpp config.h
	g++ -Wall `pkg-config --cflags SDL_net` -c ipxgw.cpp

clean:
	rm -fv *.o ipxgw

install: ipxgw
	$(info Installing...)
#Requiring user rights for pcap
#Make sure that the group exists
	@groupadd -f pcap
ifneq (,$(PCAPUSER))
	usermod -a -G pcap $(PCAPUSER)
endif
	$(INSTALL) -m 0755 ipxgw $(bindir)
	$(info Adding pcap rights...)
#Set the pcap rights to the app!
	@chgrp pcap $(bindir)/ipxgw
	@setcap cap_net_raw,cap_net_admin=eip $(bindir)/ipxgw