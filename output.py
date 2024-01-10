import struct
import socket

protocol_dict = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    # 可以根据需要添加其他协议和对应的编号
}

def parse_ip_packet(packet,logfile_path):
    # 解析 IP 头部
    ip_header = struct.unpack('!BBHHHBBH4s4s', packet[:20])
    version_ihl = ip_header[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4
    ttl = ip_header[5]
    protocol = ip_header[6]
    src_ip = socket.inet_ntoa(ip_header[8])
    dest_ip = socket.inet_ntoa(ip_header[9])
    
    if version == 6:
        return

    #有键值对应则正常输出，无则输出Unknown Protocol
    protocol_value = protocol_dict.get(protocol, "Unknown Protocol") 

    print("┌──────────────── IP Header ────────────────┐")
    print(f"│ Version: {version}",end=" ")
    print(f"│ IHL: {ihl} bytes",end=" ")
    print(f"│ TTL: {ttl}")
    print(f"│ Protocol: {protocol_value}")
    print(f"│ Source IP: {src_ip}  ----→  Destination IP: {dest_ip}")
    print("└──────────────────────────────────────────┘")

    # 根据协议字段解析 TCP 头部
    if protocol == 6:  # 6 表示 TCP 协议
        tcp_header = struct.unpack('!HHIIBBHHH', packet[ihl:ihl+20])
        src_port = tcp_header[0]
        dest_port = tcp_header[1]
        sequence_number = tcp_header[2]
        acknowledgment_number = tcp_header[3]
        data_offset_reserved_flags = tcp_header[4]
        data_offset = (data_offset_reserved_flags >> 4) * 4
        flags = tcp_header[5]
        window_size = tcp_header[6]
        checksum = tcp_header[7]
        urgent_pointer = tcp_header[8]

        print("┌──────────────── TCP Header ────────────────┐")
        print(f"│ Source Port: {src_port}  ----→  Destination Port: {dest_port}")
        print(f"│ Sequence Number: {sequence_number}",end=" ")
        print(f"│ Acknowledgment Number: {acknowledgment_number}",end=" ")
        print(f"│ Data Offset: {data_offset} bytes")
        print(f"│ Flags: {flags}",end=" ")
        print(f"│ Window Size: {window_size}",end=" ")
        print(f"│ Checksum: {checksum}",end=" ")
        print(f"│ Urgent Pointer: {urgent_pointer}")
        print("└────────────────────────────────────────────┘")

        # 提取数据字段
        data = packet[ihl + data_offset:]
        #print("┌──────────────── DATA ────────────────┐")
        #print(f"│ Data: {data}")
        #print("└──────────────────────────────────────┘")

        with open(logfile_path,'a') as file:
            file.write("┌──────────────── IP Header ────────────────┐\n")
            file.write(f"│ Version: {version}")
            file.write(f"│ IHL: {ihl} bytes")
            file.write(f"│ TTL: {ttl}\n")
            file.write(f"│ Protocol: {protocol_dict[protocol]}\n")
            file.write(f"│ Source IP: {src_ip}  ----→  Destination IP: {dest_ip}\n")
            file.write("└───────────────────────────────────────────┘\n")

            file.write("┌──────────────── TCP Header ────────────────┐\n")
            file.write(f"│ Source Port: {src_port}  ----→  Destination Port: {dest_port}\n")
            file.write(f"│ Sequence Number: {sequence_number}")
            file.write(f"│ Acknowledgment Number: {acknowledgment_number}")
            file.write(f"│ Data Offset: {data_offset} bytes\n")
            file.write(f"│ Flags: {flags}")
            file.write(f"│ Window Size: {window_size}")
            file.write(f"│ Checksum: {checksum}")
            file.write(f"│ Urgent Pointer: {urgent_pointer}\n")
            file.write("└────────────────────────────────────────────┘\n")

            file.write("┌──────────────── DATA ────────────────┐\n")
            file.write(f"│ Data: {data}\n")
            file.write("└──────────────────────────────────────┘\n")
            file.write("\n")
            file.write("\n")

    # 根据协议字段解析 UDP 头部
    elif protocol == 17:  # 17 表示 UDP 协议
        udp_header = struct.unpack('!HHHH', packet[ihl:ihl+8])
        src_port = udp_header[0]
        dest_port = udp_header[1]
        length = udp_header[2]
        checksum = udp_header[3]

        print("┌──────────────── UDP Header ────────────────┐")
        print(f"│ Source Port: {src_port}  ----→  Destination Port: {dest_port}")
        print(f"│ Length: {length}")
        print(f"│ Checksum: {checksum}")
        print("└────────────────────────────────────────────┘")

        # 提取数据字段
        data = packet[ihl + 8:]
        #print("┌──────────────── DATA ────────────────┐")
        #print(f"│ Data: {data}")
        #print("└──────────────────────────────────────┘")


        with open(logfile_path,'a') as file:
            file.write("┌──────────────── IP Header ────────────────┐\n")
            file.write(f"│ Version: {version}")
            file.write(f"│ IHL: {ihl} bytes")
            file.write(f"│ TTL: {ttl}\n")
            file.write(f"│ Protocol: {protocol_dict[protocol]}\n")
            file.write(f"│ Source IP: {src_ip}  ----→  Destination IP: {dest_ip}\n")
            file.write("└───────────────────────────────────────────┘\n")

            file.write("┌──────────────── UDP Header ────────────────┐\n")
            file.write(f"│ Source Port: {src_port}  ----→  Destination Port: {dest_port}\n")
            file.write(f"│ Length: {length}")
            file.write(f"│ Checksum: {checksum}\n")
            file.write("└────────────────────────────────────────────┘\n")

            file.write("┌──────────────── DATA ────────────────┐\n")
            file.write(f"│ Data: {data}\n")
            file.write("└──────────────────────────────────────┘\n")
            file.write("\n")
            file.write("\n")

    # 根据协议字段解析 ICMP 头部
    elif protocol == 1:  # 1 表示 ICMP 协议
        icmp_header = struct.unpack('!BBHHH', packet[ihl:ihl+8])
        icmp_type = icmp_header[0]
        code = icmp_header[1]
        checksum = icmp_header[4]

        print("┌──────────────── ICMP Header ────────────────┐")
        print(f"│ ICMP Type: {icmp_type}")
        print(f"│ Code: {code}")
        print(f"│ Checksum: {checksum}")
        print("└─────────────────────────────────────────────┘")

        # 提取数据字段
        data = packet[ihl + 8:]
        #print("┌──────────────── DATA ────────────────┐")
        #print(f"│ Data: {data}")
        #print("└──────────────────────────────────────┘")


        with open(logfile_path,'a') as file:
            file.write("┌──────────────── IP Header ────────────────┐\n")
            file.write(f"│ Version: {version}")
            file.write(f"│ IHL: {ihl} bytes")
            file.write(f"│ TTL: {ttl}\n")
            file.write(f"│ Protocol: {protocol_dict[protocol]}\n")
            file.write(f"│ Source IP: {src_ip}  ----→  Destination IP: {dest_ip}\n")
            file.write("└───────────────────────────────────────────┘\n")

            file.write("┌──────────────── ICMP Header ────────────────┐\n")
            file.write(f"│ ICMP Type: {icmp_type}")
            file.write(f"│ Code: {code}")
            file.write(f"│ Checksum: {checksum}\n")
            file.write("└─────────────────────────────────────────────┘\n")
            
            file.write("┌──────────────── DATA ────────────────┐\n")
            file.write(f"│ Data: {data}\n")
            file.write("└──────────────────────────────────────┘\n")
            file.write("\n")
            file.write("\n")

    print()
    print("│ ================================================================================ │")
