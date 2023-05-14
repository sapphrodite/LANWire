#ifdef _WIN32
#  include <WinSock2.h>
#  include <Ws2tcpip.h>
#  pragma comment(lib, "Ws2_32.lib")
#else

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
	using SOCKET = int;
	using SOCKADDR = sockaddr;
	#define INVALID_SOCKET -1
#endif
#include <cstring>
#include <cstdlib>
#include <iostream>
#include "bitarray.h"

#define MAXMSGLEN 4096 // should not exceed 65535 with current design
#define HEADERLEN 6
#define RECVBUFLEN (MAXMSGLEN + HEADERLEN)

struct message {
	char buffer[RECVBUFLEN];
	size_t len = 0;
};

struct client {
	sockaddr_in addr;
	std::array<message, 64> messages;
	std::array<uint32_t, 64> timestamps;
	bitarray<64> acks;
	bool gave_clients = false;
};


struct handle {
	SOCKET sockfd = INVALID_SOCKET;
	sockaddr_in sockaddr;
	char recvbuf[RECVBUFLEN];
	std::vector<client> clients;
	std::vector<message> queue;
};

handle* alloc_handle() { return new handle; }
void free_handle(handle* hnd) { delete hnd; }


bool valid_addr(const char* addrbuf) {
	char buf[64];
	return inet_pton(AF_INET, addrbuf, buf) == 1;
}


uint32_t& getip(sockaddr_in* sock) {
#ifdef _WIN32
	return sock->sin_addr.S_un.S_addr;
#else
	return sock->sin_addr.s_addr;
#endif
}

void netinit() {
#ifdef _WIN32
    WSADATA wsaData;
    int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (res != NO_ERROR) {
        return 1;
    }
#endif
}

static uint32_t timestamp = 1;
uint32_t get_timestamp() {
	return timestamp++;
}


sockaddr_in make_sockaddr(const char* addr, uint16_t port) {
	sockaddr_in sockaddr;
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(port);
    inet_pton(AF_INET, addr, &(sockaddr.sin_addr));
	return sockaddr;
}

int initialize(handle* hnd, uint16_t port) {
	netinit();

    hnd->sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (hnd->sockfd == INVALID_SOCKET) {
    	printf("allocating socket failed\n");
		exit(1);
    }

	hnd->sockaddr = make_sockaddr("127.0.0.1", port);
    if (bind(hnd->sockfd, (SOCKADDR*) &hnd->sockaddr, sizeof(hnd->sockaddr))) {
        printf("binding socket failed\n");
		exit(1);
    }

    u_long iMode = 1;
	#ifdef _WIN32
    	int res = ioctlsocket(hnd->sockfd, FIONBIO, &iMode);
    	if (res != NO_ERROR) {
	        printf("ioctlsocket failed with error: %ld\n", WSAGetLastError());
			exit(1);
	    }
	#else
		int res = ioctl(hnd->sockfd, FIONBIO, &iMode);
	#endif

    return 0;
}

bool is_self(handle* hnd, sockaddr_in addr) {
 	return (getip(&(hnd->sockaddr)) == getip(&addr) && hnd->sockaddr.sin_port == addr.sin_port);
}

int matchaddr(handle* hnd, sockaddr_in addr) {
	int index = -1;
    for (int i = 0; i < hnd->clients.size(); i++)
        if (getip(&(hnd->clients[i].addr)) == getip(&addr) && hnd->clients[i].addr.sin_port == addr.sin_port)
            index = i;
    return index;
}

void add_peer(handle* hnd, sockaddr_in addr) {
	if (matchaddr(hnd, addr) != -1 || is_self(hnd, addr))
		return;

	auto& c = hnd->clients.emplace_back(client());
	c.addr = addr; 
}

void add_peer(handle* hnd, const char* addr, uint16_t port) { add_peer(hnd, make_sockaddr(addr, port)); }

int alloc_msgid(client& c) {
	int msgid = c.acks.least_unset_bit();
	c.acks.set(msgid);
	return msgid;
}
	
void queuemsg(client& c, const char* buffer, size_t buflen) {
	int msgid = alloc_msgid(c);
	memset(c.messages[msgid].buffer, 0, RECVBUFLEN);
	c.messages[msgid].buffer[1] = msgid;
	c.messages[msgid].len = buflen + HEADERLEN;
	uint32_t timestamp = get_timestamp();

	memcpy(c.messages[msgid].buffer + 2, &timestamp, 4);
	memcpy(c.messages[msgid].buffer + HEADERLEN, buffer, buflen);
	printf("Transmitting message %s\n", c.messages[msgid].buffer + HEADERLEN);
}

void sendack(handle* hnd, int clientid, int msgid) {
	char buf[HEADERLEN];
	buf[0] = 0x1;
	buf[1] = msgid;
	sendto(hnd->sockfd, buf, sizeof(buf), 0, (SOCKADDR*) &(hnd->clients[clientid].addr), sizeof(sockaddr));
}

void recvack(handle* hnd, int clientid, int msgid) { hnd->clients[clientid].acks.clear(msgid); }


void request_peers(handle* hnd) {
	char buf[HEADERLEN] = {2, 0, 0, 0, 0, 0};
	for (auto& c : hnd->clients) {
		if (!c.gave_clients)
		sendto(hnd->sockfd, buf, sizeof(buf), 0, (SOCKADDR*) &(c.addr), sizeof(sockaddr));
	}
}

sockaddr_in decode_peer(handle* hnd, const char* buf) {
	sockaddr_in peer;
    getip(&peer) = buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
	peer.sin_port = buf[4] | (buf[5] << 8);
	return peer;
}

void read_peers(handle* hnd, const char* buf, size_t buflen) {
	for (int i = 0; i < buflen; i += 6) {
		add_peer(hnd, decode_peer(hnd, buf + i));
	}
}

void encode_peer(sockaddr_in* peer, char* buf) {
    buf[0] = (getip(peer)) & 0xFF;
	buf[1] = (getip(peer) >> 8) & 0xFF;
	buf[2] = (getip(peer) >> 16) & 0xFF;
	buf[3] = (getip(peer) >> 24) & 0xFF;
	buf[4] = peer->sin_port & 0xFF;
	buf[5] = peer->sin_port >> 8;
}

void send_peers(handle* hnd, int clientid) {
	int buflen = 6 * (hnd->clients.size()) + HEADERLEN;
	char* buf = (char*) malloc(buflen);
	memset(buf, 0, buflen);
	buf[0] = 0x3;
	for (int i = 0; i < hnd->clients.size(); i++) {
		encode_peer(&hnd->clients[i].addr, buf + (i * 6) + HEADERLEN);
	}

	sendto(hnd->sockfd, buf, buflen, 0, (SOCKADDR*) &(hnd->clients[clientid]), sizeof(sockaddr));
	free(buf);
}

bool can_request_peers(handle* hnd) {
	for (auto& c : hnd->clients)
		if (!c.gave_clients)
			return true;
	return false;
}

bool cmp_timestamp(handle* hnd, const char* buffer, int clientid) {
	uint32_t new_timestamp = (buffer[2] << 24) | (buffer[3] << 16) | (buffer[4] << 8) | buffer[5];
	uint32_t old_timestamp = hnd->clients[clientid].timestamps[buffer[1]];
	hnd->clients[clientid].timestamps[buffer[1]] = new_timestamp;
	return old_timestamp != new_timestamp;
}

int poll_clients(handle* hnd, const char** msgbuf, size_t* buflen) {
	memset(hnd->recvbuf, 0, RECVBUFLEN);
	*msgbuf = 0;
	*buflen = 0;

	socklen_t addrlen = sizeof(sockaddr_in);
	sockaddr_in addr_in;
	int recvlen = 12345;
	recvlen = recvfrom(hnd->sockfd, hnd->recvbuf, RECVBUFLEN, 0, (SOCKADDR*) &addr_in, &addrlen);

	if (recvlen == -1 || recvlen < HEADERLEN)
		return 0;

	// match to a client
	int clientid = matchaddr(hnd, addr_in);
	if (clientid == -1)
		add_peer(hnd, addr_in);

	switch (hnd->recvbuf[0]) {
	case 0x0: // standard msg
		sendack(hnd, clientid, hnd->recvbuf[1]);
		// test if message is new
		if (cmp_timestamp(hnd, hnd->recvbuf, clientid)) {
			*msgbuf = hnd->recvbuf + HEADERLEN;
			*buflen = recvlen - HEADERLEN;
		}
		return 0;
	case 0x1:
		recvack(hnd, clientid, hnd->recvbuf[1]);
		return 0;
	case 0x2:
		send_peers(hnd, clientid);
		return 0;
	case 0x3:
		read_peers(hnd, hnd->recvbuf + HEADERLEN, recvlen - HEADERLEN);
		hnd->clients[clientid].gave_clients = true;
		return 0;
	}
}

bool can_transmit(handle* hnd) {
	if (hnd->clients.size() == 0)
		return false;

	for (auto& c : hnd->clients) {
		if (c.acks.size() == c.acks.capacity())
			return false;
	}
	return true;
}

void dequeue_msg(handle* hnd) {
	auto it = hnd->queue.begin();
	for (auto& c : hnd->clients) {
		queuemsg(c, it->buffer, it->len);
		hnd->queue.erase(it);
	}
}

int queue_message(handle* hnd, const char* buffer, size_t len) {
	if (can_transmit(hnd)) {
		for (auto& c : hnd->clients)
			queuemsg(c, buffer, len);
	} else {
		hnd->queue.emplace_back(message());
		auto& msg = hnd->queue.back();
		memcpy(msg.buffer, buffer, len);
		msg.len = len;
	}
	return 0;
}

void transmit_all(handle* hnd) {
	while (can_transmit(hnd)) {
		if (hnd->queue.size() == 0)
			break;

		dequeue_msg(hnd);
	}

	for (auto& c : hnd->clients) {
		for (auto msgid : c.acks) {
			sendto(hnd->sockfd, c.messages[msgid].buffer, c.messages[msgid].len, 0, (SOCKADDR*) &c.addr, sizeof(sockaddr));
		}
	}
}

int main2() {
/*    socklen_t peerAddrSize = sizeof(peerAddr);

    char recvBuf[MAXMSGLEN + 2];
    int recvLen;
    char ack[2] = { 1 };
    char init[2] = { 2 };
    std::queue<char*> payloads;

    int res = initSocket(&clientAddr, &sendSocket);
    if (res != 0) {
        return res;
    }

    std::deque<std::string> lines; // protected by m
    std::deque<std::string> toProcess; // the nonblocking thread


    printf("Start new session? ");
    if (getchar() != 'y') {
        printf("Enter destination IP: ");
		readip(&peerAddr.sin_addr);
        printf("Enter destination port: ");
        peerAddr.sin_family = AF_INET;
        peerAddr.sin_port = htons(readint());
        allocatePeer(&peers, &peerAddr, &messageAcks, &messages);
        allocateMsgId(&peers, &peerAddr, init, 0, &messageAcks, &messages);
        int sendResult = sendto(sendSocket, init, 2, 0, (SOCKADDR*)&peerAddr, peerAddrSize);
    }


    toProcess.clear();
    printf("Enter message: ");

    while (1) {
        //resendAll(&peers, &messageAcks, &messages, sendSocket);
        recvLen = recvfrom(sendSocket, recvBuf, sizeof(recvBuf) - 1, 0, (SOCKADDR*)&peerAddr, &peerAddrSize);
        if (recvLen != -1) {
            if (recvBuf[0] == 1) {
                printf("Message was an ack");
                deallocateMsgId(&peers, &peerAddr, &messageAcks, recvBuf[1]);
            }
            else if (recvBuf[0] == 2 && recvLen == 2) {
                printf("Message was an init");
                printf("\nSending ack");
                ack[1] = recvBuf[1];
                int sendResult = sendto(sendSocket, ack, 2, 0, (SOCKADDR*)&peerAddr, peerAddrSize);
                allocatePeer(&peers, &peerAddr, &messageAcks, &messages);
                char sendBuf[MAXMSGLEN + 2];
                for (int i = 0; i < peers.size(); i++) {
                    encodeAddr(&(peers[i]), sendBuf, i * 6 + 2);
                }
                sendBuf[0] = 2;
                allocateMsgId(&peers, &peerAddr, sendBuf, peers.size() * 6, &messageAcks, &messages);
                sendResult = sendto(sendSocket, sendBuf, peers.size() * 6 + 2, 0, (SOCKADDR*)&peerAddr, peerAddrSize);

                char plBuf[MAXMSGLEN + 5];
                plBuf[0] = peers.size() * 6 / 64;
                plBuf[1] = peers.size() * 6 % 64;
                plBuf[3] = 2;
                encodeAddr(&peerAddr, plBuf, 5);
                for (int i = 0; i < peers.size(); i++) {
                    plBuf[2] = i;
                    payloads.push(plBuf);
                }
            }
            else if (recvBuf[0] == 2) {
                struct sockaddr_in tempAddr;
                tempAddr.sin_family = AF_INET;
                for (int i = 0; i < (recvLen - 2) / 6; i++) {
                    decodeAddr(&tempAddr, recvBuf, i * 6 + 2);
                    if (findPeer(&peers, &tempAddr) != -1) {
                        peers.push_back(tempAddr);
                    }
                }
                printf("\nSending ack");
                ack[1] = recvBuf[1];
                int sendResult = sendto(sendSocket, ack, 2, 0, (SOCKADDR*)&peerAddr, peerAddrSize);
            }
            else {
                for (int i = 2; i < recvLen; i++) {
                    printf("%c", recvBuf[i]);
                }
                printf("\nSending ack");
                ack[1] = recvBuf[1];
                int sendResult = sendto(sendSocket, ack, 2, 0, (SOCKADDR*)&peerAddr, peerAddrSize);
            }
            printf("\n");
        }

        // critical section
        std::unique_lock<std::mutex> lock{ mutex };
        if (cv.wait_for(lock, std::chrono::seconds(0), [&] { return !lines.empty(); })) {
            // get a new batch of lines to process
            std::swap(lines, toProcess);
        }

        if (!toProcess.empty()) {
            printf("Queueing message\n");
            for (auto&& line : toProcess) {
                // process lines received by io thread
                queueMsg(line, &peers, &payloads);
                printf("Enter message: ");
            }
            toProcess.clear();
        }

        if (!payloads.empty()) {
            char sendBuf[MAXMSGLEN + 2];
            int msgLen = 256 * payloads.front()[0] + payloads.front()[1];
            for (int i = 0; i < msgLen + 2; i++) {
                sendBuf[i] = payloads.front()[i + 3];
            }
            for (int i = 0; i < peers.size(); i++) {
                peerAddr = peers[payloads.front()[2]];
                allocateMsgId(&peers, &peerAddr, sendBuf, msgLen, &messageAcks, &messages);
                int sendResult = sendto(sendSocket, sendBuf, msgLen + 2, 0, (SOCKADDR*)&peerAddr, peerAddrSize);
            }
            payloads.pop();
        }
    }*/
	return 0;
}
