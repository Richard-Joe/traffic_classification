# -*- coding: utf-8 -*-
#!/usr/bin/python3

import os
import shelve
import prettytable as pt
from scapy.all import *
from collections import namedtuple


AddrAttr = namedtuple('AddrAttr', ['addr', 'port'])
PacketAttr = namedtuple('PacketAttr', ['src', 'dst', 'proto', 'payload_len'])

DIRECT_SAME = 1
DIRECT_REVERSE = 2


class ConnAttr(object):
    __slots__ = (
        '_src',
        '_dst',
        '_proto',
    )
    def __init__(self, src, dst, proto):
        self._src = src
        self._dst = dst
        self._proto = proto

    def __hash__(self):
        return hash((self._src, self._dst, self._proto))

    def __eq__(self, other):
        a = (self._src == other._src and self._dst == other._dst)
        b = (self._src == other._dst and self._dst == other._src)
        return isinstance(other, self.__class__) and \
               self._proto == other._proto and (a or b)

    def __ne__(self, other):
        return not self.__eq__(other)


class StreamAttr(object):
    __slots__ = (
        'src',
        'dst',
        'proto',
        's2d_pkg_num',
        'd2s_pkg_num',
        's2d_payload_cnt',
        'd2s_payload_cnt',
    )

    def __init__(self, src, dst, proto, s2d_pkg_num, d2s_pkg_num, s2d_payload_cnt, d2s_payload_cnt):
        self.src = src
        self.dst = dst
        self.proto = proto
        self.s2d_pkg_num = s2d_pkg_num
        self.d2s_pkg_num = d2s_pkg_num
        self.s2d_payload_cnt = s2d_payload_cnt
        self.d2s_payload_cnt = d2s_payload_cnt

    def check_direct(self, src, dst):
        if self.src == src and self.dst == dst:
            return DIRECT_SAME
        if self.src == dst and self.dst == src:
            return DIRECT_REVERSE
        raise Exception('not match')


CapAttr = namedtuple('CapAttr', ['packets', 'streams'])

suffix = ('.cap', '.pcap', '.pcapng')

layer3 = {
    6: TCP,
    17: UDP
}


class FeatureExtration(object):
    def __init__(self, dir_path):
        self.dir_path = dir_path
        self.cap_attr = dict()

    @staticmethod
    def check_suffix(filename):
        _, ext = os.path.splitext(filename)
        return ext in suffix

    def get_all_cap(self):
        filepaths = list()
        for parent, dirnames, filenames in os.walk(self.dir_path):
            for filename in filenames:
                if not self.check_suffix(filename):
                    continue
                filepaths.append(os.path.join(parent, filename))
        return filepaths

    @staticmethod
    def extra_one_cap(filepath):
        packets = list()
        streams = dict()

        cap = rdpcap(filepath)
        for item in cap:
            proto = item[IP].proto
            if not layer3.get(proto):
                print('unknown proto[%s]' % proto)
                continue

            if not item[IP].haslayer(layer3[proto]):
                payload = item[IP].payload
            else:
                payload = item[IP][layer3[proto]].payload

            if not payload:
                continue

            try:
                src = AddrAttr(item[IP].src, item[IP].sport)
                dst = AddrAttr(item[IP].dst, item[IP].dport)
            except Exception:
                continue

            payload_len = len(payload)

            packets.append(PacketAttr(
                src=src, dst=dst, proto=proto, payload_len=payload_len
            ))

            # 先试下反方向能不能找到
            conn = ConnAttr(src=dst, dst=src, proto=proto)
            if not streams.get(conn):
                # 再试下正方向
                conn = ConnAttr(src=src, dst=dst, proto=proto)
            if not streams.get(conn):
                streams[conn] = StreamAttr(
                    src=src, dst=dst, proto=proto,
                    s2d_pkg_num=1, d2s_pkg_num=0,
                    s2d_payload_cnt=payload_len, d2s_payload_cnt=0
                )
            else:
                stream = streams[conn]
                print 
                if stream.check_direct(src, dst) == DIRECT_SAME:
                    stream.s2d_pkg_num += 1
                    stream.s2d_payload_cnt += payload_len
                else:
                    stream.d2s_pkg_num += 1
                    stream.d2s_payload_cnt += payload_len

        return CapAttr(packets=packets, streams=streams)

    def run(self):
        filepaths = self.get_all_cap()
        for filepath in filepaths:
            self.cap_attr[filepath] = self.extra_one_cap(filepath)

    @staticmethod
    def get_addr(addr_attr):
        return '%s (%s)' % (addr_attr.addr, addr_attr.port)

    def show(self):
        for filepath, capattr in self.cap_attr.items():
            streams = capattr.streams
            packets = capattr.packets

            print('filepath: %s' % filepath)

            tb = pt.PrettyTable()
            tb.field_names = ['src', 'dst', 'proto', 's2d_pkg_num', 'd2s_pkg_num', 's2d_payload_cnt', 'd2s_payload_cnt',]
            for stream in streams.values():
                tb.add_row([
                    self.get_addr(stream.src), self.get_addr(stream.dst), stream.proto,
                    stream.s2d_pkg_num, stream.d2s_pkg_num, stream.s2d_payload_cnt, stream.d2s_payload_cnt
                ])
            print(tb)

            # tb = pt.PrettyTable()
            # tb.field_names = ['src', 'dst', 'proto', 'payload_len']
            # for packet in packets:
            #     tb.add_row([self.get_addr(packet.src), self.get_addr(packet.dst), packet.proto, packet.payload_len])
            # print(tb)

            print()


def main():
    fe = FeatureExtration('./cap')
    fe.run()
    fe.show()


if __name__ == '__main__':
    main()
