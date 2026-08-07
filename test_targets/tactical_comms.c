#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PAYLOAD_SIZE 64

struct RadioPacket {
    char sender_id[16];
    char payload[MAX_PAYLOAD_SIZE];
};

void parse_packet(const char *raw_data) {
    struct RadioPacket packet;
    memset(&packet, 0, sizeof(packet));

    // The vulnerability: copying input data of arbitrary length 
    // into a fixed-size buffer without bounds checking.
    // This allows a stack-based buffer overflow.
    strcpy(packet.payload, raw_data);

    printf("[TACTICAL COMMS] Received packet from secure sender.\n");
    printf("[TACTICAL COMMS] Payload data: %s\n", packet.payload);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <packet_data>\n", argv[0]);
        return 1;
    }

    printf("[TACTICAL COMMS] Initializing Radio Link...\n");
    parse_packet(argv[1]);
    printf("[TACTICAL COMMS] Processing complete.\n");

    return 0;
}
