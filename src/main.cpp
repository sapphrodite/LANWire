#include <string>
#include <iostream>
#include <mutex>
#include <vector>
#include <thread>
#include <cstring>
#include <cassert>
#include <condition_variable>

#include "netapi.h"
#include "player.h"

int readint() {
	std::string buf; 
	char* p;

	for (;;) {
		std::getline(std::cin, buf);

        int n = strtol(buf.c_str(), &p, 10);
        if (!(p == buf.c_str() || *p != '\n')) {
	        printf("Please enter an integer: ");
        } else { 
			return n;
		}	
	}
}

std::string readip() {
	std::string buf; 
	char* p;

	for (;;) {
		std::getline(std::cin, buf);

		if (buf == "")
			continue;

		if (valid_addr(buf.c_str()))
			return buf;

		printf("Please enter a valid IP: ");
	}
}

struct filerecv {
	struct filechunk { 
		char buffer[4096];
		size_t len = 0;
	};
	char filename[64];
	int total_chunks = 0;
	std::vector<filechunk> chunks;
};


struct appdata {
	handle* nethnd = alloc_handle();
	filerecv fr;
	Sound sound;
};

void save_file(appdata& app) {
	char buffer[128];
	strcpy(buffer, "recv/");
	strcat(buffer, app.fr.filename);
	FILE* fp = fopen(buffer, "wb");

	printf("Saving file to %s\n", buffer);
	if (!fp) {
		printf("File saving failed\n");
		return;
	}
	for (auto& chunk : app.fr.chunks)
		fwrite(chunk.buffer, chunk.len, 1, fp);

	fclose(fp);
}


void send_file(appdata& app, const char* filename) {
	FILE* fp = fopen(filename, "rb");
	if (fp == NULL) {
		printf("Unable to open file \"%s\"\n", filename);
		return;
	}

	/* get file size in bytes */
	fseek(fp, 0L, SEEK_END);
	int fsize = ftell(fp);
	rewind(fp); //return cursor to beginning of file
	uint16_t numchunks = (fsize / 4000) + 1; // chunk size :)

	
	// send init cmd to server
	char buf[64];
	sprintf(buf, "cp %s %i", filename, numchunks);
	printf("Transmitting ftp init string \"%s\"\n", buf);
	queue_message(app.nethnd, buf, strlen(buf));

	char readbuf[4096];
	for (int i = 0; i < numchunks; i++) {
		int nw = sprintf(readbuf, "fc %u ", i);
//		printf("%s\n", readbuf, nw);
		size_t nread = fread(readbuf + nw + 1, 1, 4000, fp);

		queue_message(app.nethnd, readbuf, nw + 1 + nread);
	} 
	fclose(fp);
}

void parse_cmd(appdata& app, const char* cmd, size_t buflen, bool local) {
	char buffer[4096];
	strcpy(buffer, cmd); 

	const char* tokenptrs[64];
	char* pch = strtok (buffer, " ");
	size_t total_tokens = 0;
	while (pch != NULL) {
		tokenptrs[total_tokens++] = pch;
		pch = strtok (NULL, " ");
	}


	if (strcmp("queue", tokenptrs[0]) == 0) {
		assert(total_tokens > 1);
		send_file(app, tokenptrs[1]);
		app.sound.addMusic(tokenptrs[1]);
	} else if (strcmp("cp", tokenptrs[0]) == 0) {
		assert(total_tokens > 2);
		printf("received copy cmd\n");

		app.fr.total_chunks = atoi(tokenptrs[2]);
		strcpy(app.fr.filename, tokenptrs[1]);
	} else if (strcmp("fc", tokenptrs[0]) == 0) { 
		size_t bufstart = tokenptrs[2] - tokenptrs[0];
		size_t w = buflen - bufstart;
		int chunkid = atoi(tokenptrs[1]);
		if (app.fr.chunks.size() <= chunkid) {
			app.fr.chunks.resize(chunkid + 1);
		}

		printf("fc %i\n", chunkid);
		memcpy(app.fr.chunks[chunkid].buffer, cmd + bufstart, w);
		app.fr.chunks[chunkid].len = w;

		if (app.fr.total_chunks == app.fr.chunks.size()) {
			bool all_valid = true;
			for (int i = 0; i < app.fr.chunks.size(); i++) {
				if (app.fr.chunks[i].len == 0) {
	//				printf("failed at chunk %i\n", i);	
					all_valid = false;

				}
			}

			save_file(app);
			app.sound.addMusic(app.fr.filename);

			app.fr.chunks.clear();
			memset(app.fr.filename, 0, 128);
		}
	} else if (strcmp("play", tokenptrs[0]) == 0) {
		app.sound.playMusic();
		if (local)
			queue_message(app.nethnd, "play", strlen("play"));
	} else if (strcmp("pause", tokenptrs[0]) == 0) {
		app.sound.togglePause();
		if (local)
			queue_message(app.nethnd, "pause", strlen("pause"));
	} else {
		printf("Unrecognized command: %s\n", cmd);
	}

}


int main() {
	appdata app;

	printf("Enter a port number: ");	
	initialize(app.nethnd, readint());

    printf("Join existing session? ");
    if (getchar() == 'y') {
        printf("Enter destination IP: ");
		std::string ip = readip();
        printf("Enter destination port: ");
		add_peer(app.nethnd, ip.c_str(), readint());


		while (can_request_peers(app.nethnd)) {
			request_peers(app.nethnd);
			const char* msgbuf = nullptr;
			size_t buflen = 0;
			int retval = poll_clients(app.nethnd, &msgbuf, &buflen);
		}
	}

    std::condition_variable cv;
    std::mutex mutex;
	std::vector<std::string> lines; 
	bool eof = false;

    // thread to read from stdin
    std::thread io {[&] {
        std::string tmp;
        while (true) {
			if (feof(stdin))
				eof = true;

            std::getline(std::cin, tmp);
            std::lock_guard<std::mutex> lock{mutex};
            lines.emplace_back(tmp);
            cv.notify_one();

        }
    }};

	while (!eof) {
        std::unique_lock<std::mutex> lock{ mutex };
        if (cv.wait_for(lock, std::chrono::seconds(0), [&] { return !lines.empty(); })) {
			for (auto& line : lines)
				parse_cmd(app, line.c_str(), line.length(), true);
			lines.clear();
		}


		const char* msgbuf = nullptr;
		size_t buflen = 0;
		int retval = poll_clients(app.nethnd, &msgbuf, &buflen);

		if (buflen != 0)
			parse_cmd(app, msgbuf, buflen, false);
		transmit_all(app.nethnd);
	}
}
