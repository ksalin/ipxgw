all: ipxgw

ipxgw: ipxgw.o
	g++ -Wall ipxgw.o `pkg-config --libs libpcap SDL_net` -o ipxgw

ipxgw.o: ipxgw.cpp config.h
	g++ -Wall `pkg-config --cflags libpcap SDL_net` -c ipxgw.cpp

clean:
	rm -fv *.o ipxgw
