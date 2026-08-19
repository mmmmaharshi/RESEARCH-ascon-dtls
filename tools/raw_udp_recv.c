#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char** argv) {
    WSADATA wsa; SOCKET s; struct sockaddr_in a; char buf[1500]; int n;
    int port = argc > 1 ? atoi(argv[1]) : 11180;
    WSAStartup(MAKEWORD(2,2), &wsa);
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    memset(&a, 0, sizeof(a)); a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port); a.sin_addr.s_addr = INADDR_ANY;
    if (bind(s, (struct sockaddr*)&a, sizeof(a)) < 0) { printf("bind fail %d\n", WSAGetLastError()); return 1; }
    printf("raw receiver on %d\n", port);
    n = recvfrom(s, buf, sizeof(buf), 0, NULL, NULL);
    printf("recvfrom ret %d err %d\n", n, WSAGetLastError());
    closesocket(s);
    return 0;
}
