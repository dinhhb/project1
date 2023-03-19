#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PACKET_LENGTH 100
#define MAX_HDLC_FRAME_LENGTH 200
#define FLAG_FIELD 0x7E
#define ADDRESS_FIELD 0xFF
#define CONTROL_FIELD 0x03
#define INVALID_FCS 0xFF
#define ESCAPE_CHARACTER 0x7D
#define XOR_KEY 0x20

static uint16_t fcstab[256] = {
    0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
    0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
    0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
    0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
    0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
    0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
    0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
    0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
    0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
    0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
    0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
    0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
    0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
    0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
    0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
    0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
    0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
    0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
    0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
    0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
    0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
    0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
    0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
    0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
    0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
    0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
    0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
    0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
    0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
    0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
    0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
    0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};

int read_packet(unsigned char *packet, int *packet_length);
uint16_t crc16_ccitt(const unsigned char *data, int len);
int create_hdlc_frame(unsigned char *packet, int packet_length, unsigned char *hdlc_frame, int *hdlc_frame_length);
void send_hdlc_frame(unsigned char *hdlc_frame, int hdlc_frame_length);
int receive_hdlc_frame(unsigned char *hdlc_frame, int *hdlc_frame_length, uint16_t *received_fcs, uint16_t *computed_fcs);
void print_hex_string(unsigned char *str, int str_len);
void check_frame_valid(uint16_t fcs1, uint16_t fcs2);

int main(){
    unsigned char packet[MAX_PACKET_LENGTH];
    int packet_length = 0;
    unsigned char hdlc_frame[MAX_HDLC_FRAME_LENGTH];
    int hdlc_frame_length = 0;
    unsigned char hdlc_frame_received[MAX_HDLC_FRAME_LENGTH];
    int hdlc_frame_received_length = 0;
    unsigned char data_received[MAX_HDLC_FRAME_LENGTH];
    int data_received_legnth = 0;

    system("clear");
    printf("------------------------------------------------------------------------\n");
    printf("HDLC Protocol Simulation\n");
    printf("------------------------------------------------------------------------\n");


    // Initialize the packet
    if (read_packet(packet, &packet_length) != 0){
        printf("Error: Failed to read packet data\n");
        return 1;
    }

    // Create the HDLC frame
    if (create_hdlc_frame(packet, packet_length, hdlc_frame, &hdlc_frame_length) != 0){
        printf("Error: Failed to create HDLC frame\n");
        return 1;
    }
    else printf("\nSuccessfully created HDLC frame\n");

    // Send the HDLC frame
    send_hdlc_frame(hdlc_frame, hdlc_frame_length);

    uint16_t received_fcs, computed_fcs;
    int x;
    do {
        // Receive the HDLC frame
        printf("\nEnter received HDLC frame in hexadecimal: ");
        x = receive_hdlc_frame(hdlc_frame_received, &hdlc_frame_received_length, &received_fcs, &computed_fcs);
    } while (x != 0);

    check_frame_valid(received_fcs, computed_fcs);
    printf("------------------------------------------------------------------------\n");

    return 0;
}

int read_packet(unsigned char *packet, int *packet_length){
    FILE *fp;
    int i = 0;

    fp = fopen("packet.txt", "r");
    if (fp == NULL){
        printf("Error: Failed to open file\n");
        return 1;
    }

    while (fscanf(fp, "%2hhx", &packet[i]) == 1){
        i++;
    }

    fclose(fp);
    *packet_length = i;

    return 0;
}

uint16_t crc16_ccitt(const unsigned char *data, int len){
    uint16_t crc = 0xFFFF;

    printf("\nInput buffer for calculating fcs: ");
    for (int i = 0; i < len; i++) {
        crc = (crc >> 8) ^ fcstab[(crc ^ data[i]) & 0xff];
        printf("%02X ", data[i]);
    }
    printf("\n");
    return crc;
}

int create_hdlc_frame(unsigned char *packet, int packet_length, unsigned char *hdlc_frame, int *hdlc_frame_length){

    // Check for invalid packet length
    if (packet_length <= 0 || packet_length > MAX_PACKET_LENGTH){
        printf("Error: Invalid packet length\n");
        return 1;
    }

    int j = 0;
    hdlc_frame[j++] = FLAG_FIELD;
    hdlc_frame[j++] = ADDRESS_FIELD;
    hdlc_frame[j++] = CONTROL_FIELD;

    printf("Control = %02X\n", hdlc_frame[j-1]);

    for (int i = 0; i < packet_length; i++){
        unsigned char c = packet[i];
        if (c == FLAG_FIELD || c == ESCAPE_CHARACTER){
            hdlc_frame[j++] = ESCAPE_CHARACTER;
            hdlc_frame[j++] = c ^ XOR_KEY;
        }
        else{
            hdlc_frame[j++] = c;
        }
    }

    unsigned char buffer[MAX_HDLC_FRAME_LENGTH]; // buffer to store address, control and information field of an hdlc frame
    int buffer_length = packet_length + 2;
    int k = 0;

    buffer[k++] = ADDRESS_FIELD;

    // Copy control field
    buffer[k++] = CONTROL_FIELD;

    // Copy information field
    for (int i = 0; i < buffer_length; i++) {
        buffer[k++] = packet[i];
    }

    // printf("Buffer: ");
    // print_hex_string(buffer, buffer_length);
    printf("Packet received: ");
    print_hex_string(packet, packet_length);

    // FCS
    uint16_t fcs = crc16_ccitt(buffer, buffer_length);
    printf("FCS value of sending frame = %02X\n", fcs);

    if (fcs == INVALID_FCS){
        printf("Error: Invalid FCS value\n");
        return 2;
    }

    hdlc_frame[j++] = (fcs >> 8) & 0xFF;
    hdlc_frame[j++] = fcs & 0xFF;
    hdlc_frame[j++] = FLAG_FIELD;
    *hdlc_frame_length = j;
    // printf("HDLC frame length = %d\n", j);

    return 0;
}

void send_hdlc_frame(unsigned char *hdlc_frame, int hdlc_frame_length){
    // Placeholder function to simulate sending the HDLC frame
    printf("Sending HDLC frame: ");
    print_hex_string(hdlc_frame, hdlc_frame_length);
    printf("...Done sending frame\n");
}

int receive_hdlc_frame(unsigned char *hdlc_frame, int *hdlc_frame_length, uint16_t *received_fcs, uint16_t *computed_fcs){
    char buffer[100];
    int buffer_length = 0;

    // Read the data into the buffer
    scanf("%s", buffer);
    buffer_length = strlen(buffer);
    *hdlc_frame_length = buffer_length / 2;

    // Check for invalid buffer length
    if (buffer_length % 2 != 0 || buffer_length / 2 > MAX_HDLC_FRAME_LENGTH)
    {
        printf("Error: Invalid buffer length. Try again!\n");
        return 1;
    }

    // Convert the hexadecimal string to binary data
    for (int i = 0; i < buffer_length; i += 2){
        if (sscanf(buffer + i, "%2hhx", &hdlc_frame[i / 2]) != 1)
        {
            printf("Error: Invalid hexadecimal data. Try again!\n");
            return 2;
        }
    }

    printf("Received HDLC frame: ");
    print_hex_string(hdlc_frame, *hdlc_frame_length);
    // printf("\nReceived hdlc frame length: %d\n", *hdlc_frame_length);

    // Check start and end flags
    if (hdlc_frame[0] != FLAG_FIELD || hdlc_frame[*hdlc_frame_length - 1] != FLAG_FIELD){
        printf("Error: Invalid start or end flag. Try again!\n");
        return 3;
    }

    // Check address and control field
    if (hdlc_frame[1] != ADDRESS_FIELD || hdlc_frame[2] != CONTROL_FIELD){
        printf("Error: Invalid address or control field. Try again!\n");
        return 4;
    }

    printf("...Done receiving frame\n");

    // Copy address field
    unsigned char buffer1[MAX_HDLC_FRAME_LENGTH];
    int j = 0;
    buffer1[j++] = hdlc_frame[1];

    // Copy control field
    buffer1[j++] = hdlc_frame[2];

    // Copy information field
    for (int i = 3; i < *hdlc_frame_length - 2; i++) {
        // Check for and handle byte stuffing
        if (hdlc_frame[i] == ESCAPE_CHARACTER) {
            if (hdlc_frame[i+1] == (FLAG_FIELD ^ XOR_KEY)){     // Check if next byte is 5E
                buffer1[j++] = FLAG_FIELD;
                i++;
            }
            else{
                buffer1[j++] = ESCAPE_CHARACTER;
            }
        } else {
            buffer1[j++] = hdlc_frame[i];
        }
    }

    int buffer1_length = j - 1;
    // printf("\nInput buffer for calculating fcs: ");
    // print_hex_string(buffer1, buffer1_length);

    *computed_fcs = crc16_ccitt(buffer1, buffer1_length);
    *received_fcs = hdlc_frame[*hdlc_frame_length - 3] << 8 | hdlc_frame[*hdlc_frame_length - 2];
    printf("FCS value of received frame = %02X\n", *received_fcs);
    printf("Computed FCS value on received frame = %02X\n", *computed_fcs);

    return 0;
}

void print_hex_string(unsigned char *str, int str_len){
    for (int i = 0; i < str_len; i++){
        printf("%02X ", str[i]);
    }
    printf("\n");
}

void check_frame_valid(uint16_t fcs1, uint16_t fcs2){
    if (fcs1 == fcs2){
        printf("\nValid frame\nSending ACK to the sender...\n");
    }
    else{
        printf("\nInvalid frame\nSending NAK to the sender\nRequesting retransmission of the frame...\n");
    }
}

// Correct frame            7EFF03127D5E7D5E34567871467E

// Wrong FCS value          7EFF03127D5E7D5E34567875767E
// (Incorrect frame) 

// Missing flag field       FF03127D5E7D5E34567871467E

// Missing address field    7E03127D5E7D5E34567871467E

// Invalid buffer length    7EFF03127D5E7D5E3456787467E
