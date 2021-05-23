import socket
import struct
import random
from dataclasses import dataclass
import argparse


@dataclass
class IcmpPacket:
    packet_type: int
    code: int

    def get_checksum(self) -> int:
        packet_octets = struct.pack('!2BH', self.packet_type, self.code, 0)
        acc = 0
        for i in range(0, len(packet_octets), 2):
            acc += (packet_octets[i] << 8) + packet_octets[i + 1]
        checksum = (acc >> 16) + (acc & 0xffff)
        return checksum & 0xffff

    def __bytes__(self):
        checksum = self.get_checksum()
        return struct.pack('!2B3H',
                           self.packet_type,
                           self.code,
                           checksum,
                           1,
                           random.randint(256, 3000))

    @staticmethod
    def from_bytes(data: bytes) -> 'IcmpPacket':
        return IcmpPacket(*struct.unpack('!BB', data[:2]))

    def is_echo_reply(self):
        return self.code == self.packet_type == 0


@dataclass
class TraceResult:
    dst: str
    n: int
    net_name: str
    as_zone: str
    country: str
    is_local: bool

    @staticmethod
    def from_whois_data(dst, n, data):
        is_local = data is None
        country = data.get('country', '') if not is_local else ''
        country = country if country.lower() != 'eu' else ''
        as_zone = data.get('origin', '') if not is_local else ''
        netname = data.get('netname', '') if not is_local else ''
        return TraceResult(dst, n, netname, country, as_zone, is_local)

    def __str__(self) -> str:
        str_trace_res = f'{self.n}. {self.dst}\r\n'
        if self.is_local:
            return str_trace_res + 'local\r\n'
        info = []
        if self.net_name:
            info.append(self.net_name)
        if self.as_zone:
            info.append(self.as_zone)
        if self.country:
            info.append(self.country)
        return str_trace_res + ', '.join(info) + '\r\n'


def get_whois_iana_data(addr):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as whois_sock:
        whois_sock.settimeout(1)
        whois_sock.connect((socket.gethostbyname('whois.iana.org'), 43))
        whois_sock.send(addr.encode(encoding='utf-8') + b'\r\n')
        try:
            iana_info = whois_sock.recv(1024).decode()
            whois_addr_start = iana_info.index('whois')
            whois_addr_end = iana_info.index('\n', whois_addr_start)
            whois_addr = \
                iana_info[whois_addr_start:whois_addr_end].replace(' ',
                                                                   '').split(
                    ':')[0]
            return whois_addr
        except (socket.timeout, ValueError):
            pass
    return ''


def get_whois_data(addr: str):
    whois_addr = get_whois_iana_data(addr)
    whois_data = {}
    if not whois_addr:
        return
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as whois_sock:
        whois_sock.settimeout(2)
        whois_sock.connect((whois_addr, 43))
        whois_sock.send(addr.encode(encoding='utf-8') + b'\r\n')
        data = b''
        while True:
            temp_data = whois_sock.recv(1024)
            if not temp_data:
                break
            data += temp_data
        try:
            data = data.decode()
        except UnicodeDecodeError:
            return {}
        for field in ('netname', 'country', 'origin'):
            try:
                field_start = data.index(field)
                field_end = data.index('\n', field_start)
                field_data = \
                    data[field_start:field_end].replace(' ', '').split(':')[1]
                whois_data[field] = field_data
            except ValueError:
                continue
    return whois_data


def trace(address):
    ttl = 1
    max_hops = 30
    try:
        address = socket.gethostbyname(address)
    except socket.gaierror:
        print('Wrong address to traceroute')
        exit(1)
    n = 1
    if address == socket.gethostbyname('localhost'):
        max_hops = 1
    while ttl <= max_hops:
        sock_sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                    socket.IPPROTO_ICMP)
        sock_receiver = socket.socket(socket.AF_INET,
                                      socket.SOCK_RAW,
                                      socket.IPPROTO_ICMP)
        sock_receiver.settimeout(5)
        sock_sender.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        sock_sender.sendto(bytes(IcmpPacket(8, 0)), (address, 80))
        try:
            data, conn = sock_receiver.recvfrom(1024)
            whois_data = get_whois_data(conn[0])
            icmp_response = IcmpPacket.from_bytes(data[20:])
            trace_result = TraceResult.from_whois_data(address, n, whois_data)
            n += 1
            yield trace_result
            ttl += 1
            if icmp_response.is_echo_reply():
                sock_sender.close()
                sock_receiver.close()
                break
        except socket.timeout:
            ttl += 1


def parse_args():
    parser = argparse.ArgumentParser(description='Traceroute util')
    parser.add_argument('host', help='Host you want to trace')
    return parser.parse_args().__dict__


if __name__ == '__main__':
    args = parse_args()
    host = args.pop('host')
    try:
        for res in trace(host):
            print(res, end='\r\n')
    except PermissionError:
        print(f'Not enough rights. Try sudo or run as admin')
        exit(1)
