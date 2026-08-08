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

    // SECURE FIX: Check the length of raw_data before copying to prevent buffer overflow.
    // We use strncpy to copy at most MAX_PAYLOAD_SIZE - 1 bytes, and manually ensure null-termination.
    if (strlen(raw_data) >= MAX_PAYLOAD_SIZE) {
        printf("[TACTICAL COMMS] [GUARD ALERT] Payload size exceeds maximum bounds. Truncating input safely.\n");
    }
    strncpy(packet.payload, raw_data, MAX_PAYLOAD_SIZE - 1);
    packet.payload[MAX_PAYLOAD_SIZE - 1] = '\0'; // Explicit null termination

    printf("[TACTICAL COMMS] Received packet from sender.\n");
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