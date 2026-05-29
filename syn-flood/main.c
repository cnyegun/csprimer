#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>

int io_read_time(FILE *f, char *buf) {
    uint32_t timestamp; 
    if (fread(&timestamp, sizeof(uint32_t), 1, f) != 1) {
        // No next package
        return 0;
    }
    time_t time = timestamp;
    struct tm *tm = localtime(&time);
    strftime(buf, 64, "%Y-%m-%d %H:%M:%S", tm);
    return 1;
}

int main() {
    FILE *f = fopen("synflood.pcap", "rb");

    uint32_t magic_number;
    fread(&magic_number, sizeof(uint8_t), 4, f); 
    printf("Magic number: 0x%02x\n", magic_number);

    uint16_t major_version, minor_version;
    fread(&major_version, sizeof(uint16_t), 1, f);
    fread(&minor_version, sizeof(uint16_t), 1, f);
    printf("Version: %u.%u\n", major_version, minor_version);

    // Skips reserved bytes
    fseek(f, 2 * sizeof(uint32_t), SEEK_CUR);

    // Skips snapshot length
    fseek(f, sizeof(uint32_t), SEEK_CUR);

    // Skips additional info
    fseek(f, sizeof(uint32_t), SEEK_CUR);


    size_t total_pkg = 0;
    size_t total_ack = 0;
    size_t total_syn = 0;
    // Loop through packages try to read them
    while (1) {
        // Package header
        char time_buf[64];
        if (!io_read_time(f, time_buf)) {
            break;
        }
        printf("Timestamp: %s\n", time_buf);

        // Skip microseconds timestamp
        fseek(f, sizeof(uint32_t), SEEK_CUR);

        // Length of this package
        uint32_t captured_length, original_length;
        fread(&captured_length, sizeof(uint32_t), 1, f);
        fread(&original_length, sizeof(uint32_t), 1, f);
        printf("Length: %u bytes\n", captured_length);

        uint8_t *package = malloc(sizeof(uint8_t) * captured_length);
        fread(package, sizeof(uint8_t), captured_length, f);

        uint32_t proto;
        memcpy(&proto, package, 4);
        if (proto == 2) {
            printf("Protocol: IPv4\n");
        }
        uint8_t ver = package[4] >> 4;
        printf("IPv4 version: %u\n", ver);
        uint8_t ihl = package[4] & 0xf;
        printf("IHL: %u\n", ihl);
        uint16_t total_length;
        memcpy(&total_length, package + 6, sizeof(uint16_t));
        total_length = ntohs(total_length);
        printf("total length: %u\n", total_length);
        
        uint8_t ipv4_protocol;
        memcpy(&ipv4_protocol, package + 4 + 9, sizeof(uint8_t));
        printf("ipv4 protocol: %u\n", ipv4_protocol);
        // Jump to the TCP header
        uint8_t *tcp_begin = package + 4 + 4*ihl;
        uint8_t tcp_flags = tcp_begin[13];
        if (tcp_flags == 0x02) {
            total_syn++;
        }
        else if (tcp_flags == 0x12) {
            total_ack++;
        }

        total_pkg++;
        free(package);
    }
    printf("Total package: %lu\n", total_pkg);
    printf("ACK/SYN = %.2lf %%\n", (double)total_ack/(double)total_syn * 100);
    return 0;
}
