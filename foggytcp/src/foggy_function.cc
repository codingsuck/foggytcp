/* Copyright (C) 2024 Hong Kong University of Science and Technology

This repository is used for the Computer Networks (ELEC 3120) 
course taught at Hong Kong University of Science and Technology. 

No part of the project may be copied and/or distributed without 
the express permission of the course staff. Everyone is prohibited 
from releasing their forks in any public places. */

#include <deque>
#include <cstdlib>
#include <cstring>
#include <cstdio>

#include "foggy_function.h"
#include "foggy_backend.h"


#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))

#define DEBUG_PRINT 1
#define debug_printf(fmt, ...)                            \
  do {                                                    \
    if (DEBUG_PRINT) fprintf(stdout, fmt, ##__VA_ARGS__); \
  } while (0)


/**
 * Updates the socket information to represent the newly received packet.
 *
 * In the current stop-and-wait implementation, this function also sends an
 * acknowledgement for the packet.
 *
 * @param sock The socket used for handling packets received.
 * @param pkt The packet data received by the socket.
 */
void on_recv_pkt(foggy_socket_t *sock, uint8_t *pkt) {
    foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)pkt;
    uint8_t flags = get_flags(hdr);
    uint16_t rec_payload_len = get_payload_len(pkt);
    uint32_t rec_seq_num = get_seq(hdr);
    
    if (flags && ACK_FLAG_MASK) 
    {
        uint32_t ack = get_ack(hdr);
        printf("Receive ACK %d\n", ack);

        printf("new last_ack_received: %u, advertised_window: %u\n",
               sock->window.last_ack_received, sock->window.advertised_window);

        while (!sock->send_window.empty()) {  // check if the window is empty. If not empty, slide window
            send_window_slot_t &slot = sock->send_window.front();
            foggy_tcp_header_t *slot_hdr = (foggy_tcp_header_t *)slot.msg;
            uint16_t slot_payload_len = get_payload_len(slot.msg);
            uint32_t slot_seq_num = get_seq(slot_hdr);
            uint32_t end_seq = slot_seq_num + slot_payload_len;

            if (end_seq > ack) 
            {
              break;
            } 
            else 
            {
              sock->send_window.pop_front();
              free(slot.msg);
            }
        }

        sock->window.last_ack_received = ack;
    }

    if (rec_payload_len > 0) {
        debug_printf("Received data packet %d %d\n", rec_seq_num, rec_seq_num + rec_payload_len);

       if (after(rec_seq_num, sock->window.next_seq_expected))
       {
          add_receive_window(sock, pkt);
       }
       else if (rec_seq_num == sock->window.next_seq_expected)
       {
          add_receive_window(sock, pkt);
          process_receive_window(sock);
       }
       else
       {
        debug_printf("Sending ACK packet %d\n", sock->window.next_seq_expected);

        uint8_t *ack_pkt = create_packet(
            sock->my_port, ntohs(sock->conn.sin_port),
            sock->window.last_byte_sent, sock->window.next_seq_expected,
            sizeof(foggy_tcp_header_t), sizeof(foggy_tcp_header_t), ACK_FLAG_MASK,
            MAX(MAX_NETWORK_BUFFER - (uint32_t)sock->received_len, MSS), 0,
            NULL, NULL, 0);
        sendto(sock->socket, ack_pkt, sizeof(foggy_tcp_header_t), 0,
               (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
        free(ack_pkt);
       }
    }
}



/**
 * Breaks up the data into packets and sends a single packet at a time.
 *
 * You should most certainly update this function in your implementation.
 *
 * @param sock The socket to use for sending data.
 * @param data The data to be sent.
 * @param buf_len The length of the data being sent.
 */
void send_pkts(foggy_socket_t *sock, uint8_t *data, int buf_len) {
    uint8_t *data_offset = data;

    while (buf_len > 0) 
    {
        uint32_t window_size = MIN(sock->window.congestion_window, sock->window.advertised_window);
        uint32_t bytes_in_flight = sock->window.last_byte_sent - sock->window.last_ack_received;
        uint32_t available_window = window_size - bytes_in_flight;

        printf("Window size: %u, Bytes in flight: %u, Available window: %u\n",
        window_size, bytes_in_flight, available_window);

        if (available_window == 0) 
        {
            break;
        }

        uint16_t payload_len = MIN(buf_len, MIN((int)MSS, (int)available_window));

        send_window_slot_t slot;
        slot.is_sent = 0;
        slot.msg = create_packet(
            sock->my_port, ntohs(sock->conn.sin_port),
            sock->window.last_byte_sent, 0,
            sizeof(foggy_tcp_header_t), sizeof(foggy_tcp_header_t) + payload_len,
            NO_FLAG,
            MAX(MAX_NETWORK_BUFFER - (uint32_t)sock->received_len, MSS), 0, NULL,
            data_offset, payload_len);

        sock->send_window.push_back(slot);

        sock->window.last_byte_sent += payload_len;
        buf_len -= payload_len;
        data_offset += payload_len;
    }

    transmit_send_window(sock);
}




void add_receive_window(foggy_socket_t *sock, uint8_t *pkt) {
    foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)pkt;
    uint32_t seq_num = get_seq(hdr);
    uint16_t payload_len = get_payload_len(pkt);

    // check whether the slot is used
    for (int i = 0; i < RECEIVE_WINDOW_SLOT_SIZE; i++) 
    {
        receive_window_slot_t *slot = &(sock->receive_window[i]);
        if (!slot->is_used) 
        {
            slot->is_used = 1;
            slot->seq_num = seq_num;
            slot->payload_len = payload_len;
            slot->msg = (uint8_t*) malloc(get_plen(hdr));
            memcpy(slot->msg, pkt, get_plen(hdr));
            break;
        }
    }
}


void process_receive_window(foggy_socket_t *sock) {
    printf("process_receive_window called\n");
    printf("next_seq_expected: %u, received_len: %d\n", sock->window.next_seq_expected, sock->received_len);
    
    bool is_updated = true;
    //while it is updated, keep processing the packets if it is the desire packet

    while (is_updated) 
    {
        is_updated = false;
        for (int i = 0; i < RECEIVE_WINDOW_SLOT_SIZE; i++) 
        {
            receive_window_slot_t *slot = &(sock->receive_window[i]);
            if (slot->is_used && slot->seq_num == sock->window.next_seq_expected) 
            {
                printf("seq_num in process_receive_window: %u, payload_len: %u\n", slot->seq_num, slot->payload_len);
               
                uint16_t payload_len = slot->payload_len;
                
                sock->received_buf = (uint8_t*)
                    realloc(sock->received_buf, sock->received_len + payload_len);
                memcpy(sock->received_buf + sock->received_len, get_payload(slot->msg), payload_len);
                sock->received_len += payload_len;

                sock->window.next_seq_expected += payload_len;
                printf("Updated next_seq_expected to: %u\n", sock->window.next_seq_expected);

                slot->is_used = 0;
                free(slot->msg);
                slot->msg = NULL;
                printf("Received buffer length is now: %d\n", sock->received_len);

                is_updated = true;  
                break;  
            }
        }
    }
}


void transmit_send_window(foggy_socket_t *sock) {
    uint32_t window_size = MIN(sock->window.congestion_window, sock->window.advertised_window);
    uint32_t bytes_in_flight = sock->window.last_byte_sent - sock->window.last_ack_received;
    uint32_t available_window = window_size - bytes_in_flight;

    for (std::deque<send_window_slot_t>::iterator i = sock->send_window.begin(); i != sock->send_window.end(); i++) 
    {
        send_window_slot_t &slot = *i;
        if (!slot.is_sent && available_window >= get_payload_len(slot.msg)) 
        {
            foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)slot.msg;
            debug_printf("Sending packet %d %d\n", get_seq(hdr),
                         get_seq(hdr) + get_payload_len(slot.msg));

            slot.is_sent = 1;

            sendto(sock->socket, slot.msg, get_plen(hdr), 0,
                   (struct sockaddr *)&(sock->conn), sizeof(sock->conn));

            available_window -= get_payload_len(slot.msg);

            clock_gettime(CLOCK_MONOTONIC, &slot.send_time);
        }
    }
}

void receive_send_window(foggy_socket_t *sock) {
    // Pop out the packets that have been ACKed
    while (!sock->send_window.empty()) 
    {
        send_window_slot_t slot = sock->send_window.front();
        foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)slot.msg;

        if (!slot.is_sent || !has_been_acked(sock, get_seq(hdr))) 
        {
            break;
        }

        sock->send_window.pop_front();
        free(slot.msg);
    }
}