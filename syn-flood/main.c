#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} Output;

static void die(const char *message) {
    perror(message);
    exit(1);
}

static void out_reserve(Output *out, size_t extra) {
    if (extra > SIZE_MAX - out->len) {
        fprintf(stderr, "output buffer is too large\n");
        exit(1);
    }

    size_t needed = out->len + extra;
    if (needed <= out->cap) {
        return;
    }

    size_t cap = out->cap ? out->cap : 1 << 20;
    while (cap < needed) {
        if (cap > SIZE_MAX / 2) {
            cap = needed;
            break;
        }
        cap *= 2;
    }

    char *data = realloc(out->data, cap);
    if (!data) {
        die("realloc");
    }
    out->data = data;
    out->cap = cap;
}

static void out_write(Output *out, const char *data, size_t len) {
    out_reserve(out, len);
    memcpy(out->data + out->len, data, len);
    out->len += len;
}

static void out_str(Output *out, const char *string) {
    out_write(out, string, strlen(string));
}

static void out_u64(Output *out, uint64_t value) {
    char buf[20];
    size_t len = 0;

    do {
        buf[len++] = (char)('0' + value % 10);
        value /= 10;
    } while (value != 0);

    out_reserve(out, len);
    while (len > 0) {
        out->data[out->len++] = buf[--len];
    }
}

static void out_hex32(Output *out, uint32_t value) {
    static const char digits[] = "0123456789abcdef";
    char buf[8];

    for (int i = 7; i >= 0; --i) {
        buf[i] = digits[value & 0x0f];
        value >>= 4;
    }

    out_write(out, buf, sizeof(buf));
}

static uint16_t read_u16le(const uint8_t *p) {
    return (uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8);
}

static uint16_t read_u16be(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

static uint32_t read_u32le(const uint8_t *p) {
    return (uint32_t)p[0]
        | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16)
        | ((uint32_t)p[3] << 24);
}

static uint8_t *read_file(const char *path, size_t *size) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        die(path);
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        die("fseek");
    }

    long end = ftell(file);
    if (end < 0) {
        die("ftell");
    }

    if (fseek(file, 0, SEEK_SET) != 0) {
        die("fseek");
    }

    uint8_t *data = malloc((size_t)end);
    if (!data && end != 0) {
        die("malloc");
    }

    size_t bytes_read = fread(data, 1, (size_t)end, file);
    if (bytes_read != (size_t)end) {
        die("fread");
    }

    if (fclose(file) != 0) {
        die("fclose");
    }

    *size = (size_t)end;
    return data;
}

static const char *cached_timestamp(uint32_t timestamp, int *has_last, uint32_t *last_timestamp, char last_time[64]) {
    if (!*has_last || *last_timestamp != timestamp) {
        time_t seconds = (time_t)timestamp;
        struct tm local_time;

        if (!localtime_r(&seconds, &local_time)) {
            last_time[0] = '\0';
        } else {
            strftime(last_time, 64, "%Y-%m-%d %H:%M:%S", &local_time);
        }

        *has_last = 1;
        *last_timestamp = timestamp;
    }

    return last_time;
}

int main(void) {
    size_t pcap_size = 0;
    uint8_t *pcap = read_file("synflood.pcap", &pcap_size);

    if (pcap_size < 24) {
        free(pcap);
        fprintf(stderr, "Could not read PCAP global header\n");
        return 1;
    }

    Output out = {0};

    out_str(&out, "Magic number: 0x");
    out_hex32(&out, read_u32le(pcap));
    out_str(&out, "\nVersion: ");
    out_u64(&out, read_u16le(pcap + 4));
    out_str(&out, ".");
    out_u64(&out, read_u16le(pcap + 6));
    out_str(&out, "\n");

    size_t total_pkg = 0;
    size_t total_ack = 0;
    size_t total_syn = 0;
    size_t offset = 24;
    int has_last_timestamp = 0;
    uint32_t last_timestamp = 0;
    char last_time[64];

    while (offset + 16 <= pcap_size) {
        const uint8_t *packet_header = pcap + offset;
        uint32_t timestamp = read_u32le(packet_header);
        uint32_t captured_length = read_u32le(packet_header + 8);
        size_t packet_offset = offset + 16;
        size_t packet_length = (size_t)captured_length;

        if (packet_length > pcap_size - packet_offset) {
            break;
        }

        const uint8_t *packet = pcap + packet_offset;
        const char *time_string = cached_timestamp(timestamp, &has_last_timestamp, &last_timestamp, last_time);

        out_str(&out, "Timestamp: ");
        out_str(&out, time_string);
        out_str(&out, "\nLength: ");
        out_u64(&out, captured_length);
        out_str(&out, " bytes\n");

        if (packet_length >= 4 && read_u32le(packet) == 2) {
            out_str(&out, "Protocol: IPv4\n");
        }

        if (packet_length > 4) {
            uint8_t version_and_ihl = packet[4];
            uint8_t version = version_and_ihl >> 4;
            uint8_t ihl = version_and_ihl & 0x0f;

            out_str(&out, "IPv4 version: ");
            out_u64(&out, version);
            out_str(&out, "\nIHL: ");
            out_u64(&out, ihl);
            out_str(&out, "\n");

            if (packet_length >= 8) {
                out_str(&out, "total length: ");
                out_u64(&out, read_u16be(packet + 6));
                out_str(&out, "\n");
            }

            if (packet_length >= 14) {
                out_str(&out, "ipv4 protocol: ");
                out_u64(&out, packet[13]);
                out_str(&out, "\n");
            }

            size_t tcp_flags_offset = 4 + 4 * (size_t)ihl + 13;
            if (tcp_flags_offset < packet_length) {
                uint8_t tcp_flags = packet[tcp_flags_offset];
                if (tcp_flags == 0x02) {
                    total_syn++;
                } else if (tcp_flags == 0x12) {
                    total_ack++;
                }
            }
        }

        total_pkg++;
        offset = packet_offset + packet_length;
    }

    out_str(&out, "Total package: ");
    out_u64(&out, total_pkg);
    out_str(&out, "\n");

    char ratio_line[64];
    if (total_syn == 0) {
        snprintf(ratio_line, sizeof(ratio_line), "ACK/SYN = 0.00 %%\n");
    } else {
        snprintf(ratio_line, sizeof(ratio_line), "ACK/SYN = %.2f %%\n", (double)total_ack / (double)total_syn * 100.0);
    }
    out_str(&out, ratio_line);

    if (fwrite(out.data, 1, out.len, stdout) != out.len) {
        die("fwrite");
    }

    free(out.data);
    free(pcap);
    return 0;
}
