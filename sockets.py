# ------- Sockets and Networking ---------
import socket

from imports.cipher import AESCipher_CBC
from imports.fd import read_from_fd, write_to_fd
from imports.headers import ESPHeader, IPHeader, UDPHeader, unpack_ipv4
from imports.sha import HMACVerifier


def create_sockets(interface_name):
    # Create a RAW Socket to send the traffic
    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) #ipv4 raw tcp
    sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  #reuse addr
    sender.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) # broadcast
    sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) # diy ip header

    # Raw socket to recv the traffic
    receiver = socket.socket(  
        socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))  #
    receiver.bind((interface_name, 0))

    return sender, receiver


def send_packets(sock: socket.socket, host_ip: str, dst_ip: str, cipher: AESCipher_CBC, verifier: HMACVerifier,fd ,packets,ifnat = 0):
    ip_h = IPHeader(host_ip, dst_ip)  # create an IP header
    packet_from_fd = read_from_fd(fd)  # read the file descriptor for packets


    while packet_from_fd:
        #packet_send
        packets.append(packet_from_fd)
        
        encrypted_packet = cipher.encrypt(
            packet_from_fd)  # encrypt the packet using AES
        # create esp header with encrypted packet
        esp_h = ESPHeader(encrypted_packet) #ESPtrailer
        #verify
        hmac_generator = verifier.generate_hmac(esp_h.payload)

        # create final packet with payload
        if ifnat == 0:
            packet = (ip_h.header + esp_h.payload + hmac_generator)
        elif ifnat == 1:
            udp_h = UDPHeader(esp_h.payload)
            packet = (ip_h.header + udp_h.payload + esp_h.payload + hmac_generator)

        # send packet to destination ip
        sock.sendto(packet, (dst_ip, 0))
        # re-read from the FD and loop
        packet_from_fd = read_from_fd(fd)


def recv_packets(sock: socket.socket, host_ip: str, dst_ip: str, cipher: AESCipher_CBC,verifier: HMACVerifier, fd, packets,ifnat = 0):
    packet_from_socket = sock.recv(2048*1024)

    while packet_from_socket:
        # unpack the packet read from the FD
        if ifnat == 0:
            src, dst, protocol = unpack_ipv4(packet_from_socket[14:34])

            # protocol 50 == ESP Header
            if protocol == 50:
                hmac_verifier  = packet_from_socket[-32:]
                hmac_result = verifier.verify_hmac(packet_from_socket[34:-32],hmac_verifier)
                if hmac_result == True:
                    decrypted_packet = cipher.decrypt(
                        packet_from_socket[42:-32])  # decrypt the packet
                    
                    #packet_recv
                    packets.append(decrypted_packet)

                # write to file descriptor so it can be read and sent
                    write_to_fd(fd, decrypted_packet)
        elif ifnat == 1:
            src, dst, protocol = unpack_ipv4(packet_from_socket[22:42])

            # protocol 50 == ESP Header
            if protocol == 50:
                hmac_verifier  = packet_from_socket[-42:]
                hmac_result = verifier.verify_hmac(packet_from_socket[42:-32],hmac_verifier)
                if hmac_result == True:
                    decrypted_packet = cipher.decrypt(
                        packet_from_socket[50:-32])  # decrypt the packet
                    
                    #packet_recv
                    packets.append(decrypted_packet)

                # write to file descriptor so it can be read and sent
                    write_to_fd(fd, decrypted_packet)

        packet_from_socket = sock.recv(2048*1024)

# ------- END : Sockets and Networking ---------