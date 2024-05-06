import socket
import argparse 
import time
from struct import *
from queue import Queue
import select 
import sys
import os


# I integer (unsigned long) = 4bytes and H (unsigned short integer 2 bytes)
# see the struct official page for more info

header_format = '!IIHH'

#print the header size: total = 12
print (f'size of the header = {calcsize(header_format)}')


def create_packet(seq, ack, flags, data):
    #creates a packet with header information and application data
    #the input arguments are sequence number, acknowledgment number
    #flags (we only use 4 bits),  receiver window and application data 
    #struct.pack returns a bytes object containing the header values
    #packed according to the header_format !IIHH
    header = pack (header_format, seq, ack, flags)

    #once we create a header, we add the application data to create a packet
    #of 1472 bytes
    packet = header + data
    print (f'packet containing header + data of size {len(packet)}') #just to show the length of the packet
    return packet


def parse_header(header):
    #taks a header of 12 bytes as an argument,
    #unpacks the value based on the specified header_format
    #and return a tuple with the values
    header_from_msg = unpack(header_format, header)
    #parse_flags(flags)
    return header_from_msg
    

def parse_flags(flags):
    #we only parse the first 3 fields because we're not 
    #using rst in our implementation
    syn = flags & (1 << 3)
    ack = flags & (1 << 2)
    fin = flags & (1 << 1)
    return syn, ack, fin

import socket
import argparse
import time



# Klient kode
PACKET_SIZE= 1024
WINDOW_SIZE = 6
TIMEOUT = 0.5  # in seconds

# Function to create a DRTP packet
def create_packet(seq_num, ack_num, flags, data=b''):
    header = seq_num.to_bytes(2, 'big') + ack_num.to_bytes(2, 'big') + flags.to_bytes(2, 'big')
    max_data_size = PACKET_SIZE - len(header)
    # Truncate data if it exceeds the maximum size allowed for the data part
    data = data[:max_data_size]
    packet = header + data
    return packet


# Function to extract packet fields
def extract_fields(packet):
    seq_num, ack_num, flags = int.from_bytes(packet[:2], 'big'), int.from_bytes(packet[2:4], 'big'), int.from_bytes(packet[4:6], 'big')
    return seq_num, ack_num, flags, packet[6:]

# Function to send packet
def send_packet(sock, packet, addr):
    sock.sendto(packet, addr)

# Function to receive packet
def receive_packet(sock):
    packet, addr = sock.recvfrom(PACKET_SIZE)
    return packet, addr




# Server kode
def server(ip, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((ip, port))
    print(f"Server is listening on {ip}:{port}")
    
    syn_packet, client_addr = receive_packet(server_socket)
    print("SYN packet is received")
    seq_num, _, flags, _ = extract_fields(syn_packet)
    if flags & 0b1000:
        ack_packet = create_packet(seq_num, seq_num + 1, 0b1100)
        send_packet(server_socket, ack_packet, client_addr)
        print("SYN-ACK packet is sent")
    
    ack_packet, _ = receive_packet(server_socket)
    _, _, flags, _ = extract_fields(ack_packet)
    if flags & 0b1000:
        print("ACK packet is received")
        print("Connection established")
    
    start_time, received_data = time.time(), 0
    while True:
        packet, _ = receive_packet(server_socket)
        seq_num, _, flags, data = extract_fields(packet)
        if flags & 0b0001:
            print(f"{time.time()} -- FIN packet is received")
            send_packet(server_socket, create_packet(seq_num, seq_num + 1, 0b1000), client_addr)
            print("FIN ACK packet is sent")
            break
        else:
            print(f"{time.time()} -- packet {seq_num} is received")
            ack_packet = create_packet(seq_num, seq_num + 1, 0b1000)
            send_packet(server_socket, ack_packet, client_addr)
            print(f"{time.time()} -- sending ack for the received {seq_num}")
            received_data += len(data)
    
    end_time = time.time()
    throughput_mbps = (received_data * 8) / ((end_time - start_time) * 1000000)
    print("The throughput is {:.2f} Mbps".format(throughput_mbps))
    print("Connection Closes")
    server_socket.close()


# Client function
def client(file_path, ip, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with open(file_path, 'rb') as file:
            file_data = file.read()
    except FileNotFoundError:
        print("File not found.")
        return

    # Connection Establishment Phase
    print("Connection Establishment Phase:")
    syn_packet = create_packet(0, 0, 0b1000)
    send_packet(client_socket, syn_packet, (ip, port))
    print("SYN packet is sent")
    syn_ack_packet, _ = receive_packet(client_socket)
    seq_num, ack_num, flags, _ = extract_fields(syn_ack_packet)
    if flags & 0b1100:
        print("SYN-ACK packet is received")
        send_packet(client_socket, create_packet(seq_num, seq_num + 1, 0b1000), (ip, port))
        print("ACK packet is sent")
        print("Connection established")

    # Data Transfer
    print("\nData Transfer:")
    start_time, seq_num = time.time(), 1
    sliding_window = set()
    while file_data:
        window = min(WINDOW_SIZE, len(file_data) // PACKET_SIZE + 1)
        for _ in range(window):
            packet_data = file_data[:PACKET_SIZE]
            file_data = file_data[PACKET_SIZE:]
            send_packet(client_socket, create_packet(seq_num, 0, 0b0000, packet_data), (ip, port))
            sliding_window.add(seq_num)
            print(f"{time.time()} -- packet with seq = {seq_num} is sent, sliding window = {sliding_window}")
            seq_num += 1
            time.sleep(0.1)
            if len(sliding_window) == WINDOW_SIZE:
                ack_packet, _ = receive_packet(client_socket)
                ack_seq = int.from_bytes(ack_packet[:2], 'big')
                print(f"{time.time()} -- ACK for packet = {ack_seq} is received")
                sliding_window.remove(ack_seq)

    # Connection Teardown
    print("\nConnection Teardown:")
    send_packet(client_socket, create_packet(seq_num, 0, 0b0001), (ip, port))
    print("FIN packet is sent")
    fin_ack_packet, _ = receive_packet(client_socket)
    if int.from_bytes(fin_ack_packet[4:6], 'big') & 0b1000:
        print("FIN ACK packet is received")
    print("Connection Closes")
    client_socket.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="File transfer application using DRTP over UDP")
    parser.add_argument("-s", "--server", action="store_true", help="Run as server")
    parser.add_argument("-c", "--client", action="store_true", help="Run as client")
    parser.add_argument("-f", "--file", help="File path (client only)")
    parser.add_argument("-i", "--ip", default="127.0.0.1", help="Server IP address (client only)")
    parser.add_argument("-p", "--port", type=int, default=8088, help="Server port (both server and client)")

    args = parser.parse_args()

    if args.server:
        server(args.ip, args.port)
    elif args.client:
        if not args.file:
            parser.error("File path required in client mode")
        client(args.file, args.ip, args.port)
    else:
        parser.error ("Specify either -s for server mode or -c for client mode")









