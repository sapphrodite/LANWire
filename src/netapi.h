#ifndef NETAPI_H
#define NETAPI_H

#include <stdint.h>
#include <stddef.h>

struct handle;
handle* alloc_handle();
void free_handle(handle*);

void netinit();
bool valid_addr(const char*);

int initialize(handle*, uint16_t port);
void add_peer(handle*, const char* addr, uint16_t port);

int poll_clients(handle* hnd, const char** msgbuf, size_t* buflen);
int queue_message(handle* hnd, const char* buffer, size_t len);
void transmit_all(handle* hnd);

bool can_request_peers(handle*);
void request_peers(handle*);

#endif //NETAPI_H
