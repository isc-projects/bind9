#include <stdio.h>
#include <lwres/platform.h>
#include <Winsock2.h>

void
InitSockets(void) {
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;
 
	wVersionRequested = MAKEWORD(2, 0);
 
	err = WSAStartup( wVersionRequested, &wsaData );
	if (err != 0) {
		fprintf(stderr, "WSAStartup() failed: %d\n", err);
		exit(1);
	}
}

void
DestroySockets(void) {
	WSACleanup();
}
