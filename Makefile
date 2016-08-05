SpoofARP: SpoofARP.o ARPtools.o ARPtools.h getLocalAddress.o getLocalAddress.h
	gcc -o SpoofARP SpoofARP.o ARPtools.o getLocalAddress.o -lpcap

SpoofARP.o: SpoofARP.c ARPtools.h getLocalAddress.h
	gcc -c SpoofARP.c

ARPtools.o: ARPtools.c ARPtools.h getLocalAddress.h
	gcc -c ARPtools.c

getLocalAddress.o: getLocalAddress.c getLocalAddress.h
	gcc -c getLocalAddress.c

clean:
	rm *.o SpoofARP
