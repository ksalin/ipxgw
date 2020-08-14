all: ipxgw

ipxgw: ipxgw.o
	g++ -Wall ipxgw.o `pkg-config --libs SDL_net` -lpcap -o ipxgw

ipxgw.o: ipxgw.cpp config.h
	g++ -Wall `pkg-config --cflags SDL_net` -c ipxgw.cpp

clean:
	rm -fv *.o ipxgw
