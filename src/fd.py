import fcntl
import os
import struct


def read_from_fd(fd):
    packet = os.read(fd, 1024)
    return packet


def write_to_fd(fd, packet_from_socket):
    os.write(fd, packet_from_socket)


def initiate_tun_fd(dev_name):
    # CONSTANTS
    TUNSETIFF = 0x400454ca
    IFF_TUN = 0x0001
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000

    # Open TUN device file.
    tun = os.open('/dev/net/tun', os.O_RDWR)
    ifr = struct.pack('16sH', dev_name, IFF_TUN | IFF_NO_PI)
    ifs = fcntl.ioctl(tun, TUNSETIFF, ifr)

    return tun
