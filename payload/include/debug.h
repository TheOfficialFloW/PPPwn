#ifndef DEBUG_H
#define DEBUG_H

int sock;

void initDebugSocket(void);
void closeDebugSocket(void);

#ifdef DEBUG_SOCKET
#define printfsocket(format, ...)\
do {\
	char __printfsocket_buffer[512];\
	int __printfsocket_size = sprintf(__printfsocket_buffer, format, ##__VA_ARGS__);\
	sceNetSend(sock, __printfsocket_buffer, __printfsocket_size, 0);\
} while(0)
#else
#define printfsocket(format, ...) (void)0
#endif

void notify(char *message);

#endif
