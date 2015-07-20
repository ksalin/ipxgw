all: ipxgw

ipxgw: ipxgw.o
	g++ ipxgw.o -lpcap -lSDL -lSDL_net -o ipxgw

ipxgw.o: ipxgw.cpp config.h
	g++ -I/usr/include/SDL -c ipxgw.cpp

clean:
	rm -fv *.o ipxgw
