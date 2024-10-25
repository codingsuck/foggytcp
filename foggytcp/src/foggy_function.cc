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

    /*loss recovery
    When the packet loss happens, you should be able to detect the packet loss and recover it. 
    The sender detects the packet loss by timeout 
    (to simpify, we don’t need to consider timeout in our project) and three duplicate ACKs. 
    Then the sender should retransmit the lost packet again to recover the loss.

    if the package is sent,  sock->window.dup_ack_count will increase by 1, 
    if the  sock->window.dup_ack_count is 3, it will retransmit the package
    if the package is received,  sock->window.dup_ack_count will be reset to 0
    */
    /*if (flags && ACK_FLAG_MASK) 
    {
        if (rec_seq_num == sock->window.last_byte_sent) 
        {
            sock->window.dup_ack_count = 0;
        } 
        else 
        {
            sock->window.dup_ack_count++;
        }*/


/*
Flow control
Flow control is related to RWND and we can get the value from the header of ACK packets from receiver. 
The advertised window in the packet header is equal to RWND as shown in the following figure. 
So what you should do here is extract the advertise window size from the header. 
RWND is used to avoid that the sender sends too much packets in a short period to overflow the packet buffer of receiver. 
RWND + unprocessed packets size = buffer size. 
And, in this project, this formulation is equal to RWND + unused bytes in receive_window = receive_window size. 
So the receiver has to update RWND every time sending ACK packets.

And in the code, we use
window.advertised_window to represent the advertise window size and provide
get_advertised_window/set_advertised_window to get/set the advertised window size in the packet header.

first, get the value of window.advertised_window from the header of ACK packets from reciver
then, set buffer size = RWND + unprocessed packets size
then, set receive_window size = RWND + unused bytes in receive_window
finally, update RWND everytime ACK packet is sent in reciver

*/
    if (flags && ACK_FLAG_MASK) 
    {
        uint32_t advertised_window = get_advertised_window(hdr);
        sock->window.advertised_window = advertised_window;
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


    // for flow control
    if (sock->window.advertised_window == 0) 
    {
        sock->window.advertised_window = 65535;
    }

    /*
    loss recovery
    When the packet loss happens, you should be able to detect the packet loss and recover it. 
    The sender detects the packet loss by timeout 
    (to simpify, we don’t need to consider timeout in our project) and three duplicate ACKs. 
    Then the sender should retransmit the lost packet again to recover the loss.

    if the package is sent, sock->window.dup_ack_count will increase by 1, 
    If the sender receives three duplicate ACKs for the same packet, it indicates that the next packet in sequence has been lost. 
    The sender then retransmits the lost packet immediately.
    if the package is received,  sock->window.dup_ack_count will be reset to 0
    */
    if (sock->window.dup_ack_count == 3) 
    {
        printf("Retransmitting packet %d\n", sock->window.last_ack_received);
        for (std::deque<send_window_slot_t>::iterator i = sock->send_window.begin(); i != sock->send_window.end(); i++) 
        {
            send_window_slot_t &slot = *i;
            foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)slot.msg;
            if (get_seq(hdr) == sock->window.last_ack_received) 
            {
                sendto(sock->socket, slot.msg, get_plen(hdr), 0,
                       (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
                break;
            }
        }
    }

/*Congestion Control
Congestion control is related to CWND, which we can get the value in the sender. 
And in the code, we use windows.congestion_window to represent the congestion window size.

Congestion control is composed of three different parts: 
slow start, congestion avoidance and fast recovery. 
Then we introduce the detail of them.

Slow start: at the beginning, CWND is 1 MSS and every time the sender receives a ACK, 
CWND increases by 1 MSS. So CWND will be doubled every RTT time.

Congestion avoidance: During the slow start process, CWND is not doubled all time. 
After CWND reaches the threshold value-SSTHRESH (MSS * 64 by default), CWND only increases (MSS/CWND) MSS, 
which is equal to 1 MSS every RTT time. This process is called congestion avoidance.

Fast recovery: By default, the sender have to go back to slow start state when the sender detects three duplicate ACK or timeout 
(to simpify, we don’t need to consider timeout in our project). 
But now, we have fast recovery, which means the sender only needs to set SSTHRESH=SSTHRESH/2 and CWND=SSTHRESH+3*MSS.

at first, window.reno_state = RENO_SLOW_START. cwnd = 1 MSS, window.ssthresh = 65535, window.congestion_window = 65535 * 20, sock->window.dup_ack_count = 0
if reciver receive new ack, sock->window.dup_ack_count = 0, cwnd = cwnd + MSS and allow transmit new segment
if reciver recive duplicated ack, sock->window.dup_ack_count + 1
if reciver recive duplicated ack 3 times, window.reno_state = RENO_FAST_RECOVERY, window.ssthresh = window.ssthresh/2, cwnd = window.ssthresh + 3*MSS, retransmit the lost packet immediately
if cwnd >= sshtresh, window.reno_state = RENO_CONGESTION_AVOIDANCE, cwnd = cwnd + MSS*(MSS/cwnd), allow transmit new segment
if reciver recive duplicated ack, sock->window.dup_ack_count + 1
if reciver recive duplicated ack 3 times, window.reno_state = RENO_FAST_RECOVERY, window.ssthresh = window.ssthresh/2, cwnd = window.ssthresh + 3*MSS, retransmit the lost packet immediately
if sock-> window.dup_ack_count = 3, retransmit the lost packet immediately, ssthresh = cwnd/2, cwnd = ssthresh+3*MSS, window.reno_state = RENO_FAST_RECOVERY
if reciver receive duplicated ack, cwnd = cwnd + MSS, allow transmit new segment

*/
    if (sock->window.reno_state == RENO_SLOW_START) 
    {
        if (sock->window.dup_ack_count == 0) 
        {
            sock->window.congestion_window += MSS;
        } 
        else 
        {
            sock->window.dup_ack_count++;
        }

        if (sock->window.congestion_window >= sock->window.ssthresh) 
        {
            sock->window.reno_state = RENO_CONGESTION_AVOIDANCE;
        }
    } 
    else if (sock->window.reno_state == RENO_CONGESTION_AVOIDANCE) 
    {
        if (sock->window.dup_ack_count == 0) 
        {
            sock->window.congestion_window += MSS * (MSS / sock->window.congestion_window);
        } 
        else 
        {
            sock->window.dup_ack_count++;
        }

        if (sock->window.dup_ack_count == 3) 
        {
            sock->window.reno_state = RENO_FAST_RECOVERY;
            sock->window.ssthresh = sock->window.congestion_window / 2;
            sock->window.congestion_window = sock->window.ssthresh + 3 * MSS;
        }
    } 
    else if (sock->window.reno_state == RENO_FAST_RECOVERY) 
    {
        if (sock->window.dup_ack_count == 3) 
        {
            sock->window.ssthresh = sock->window.congestion_window / 2;
            sock->window.congestion_window = sock->window.ssthresh + 3 * MSS;
        } 
        else 
        {
            sock->window.congestion_window += MSS;
        }
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