#!/usr/bin/env python

# 导入必要的库
import argparse
import sys
import socket
import random
import struct

# 导入scapy库，用于构造和发送数据包
from scapy.all import sendp, send, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import Ether, IP, UDP
from scapy.all import IntField, FieldListField, FieldLenField, BitField, ShortField, PacketListField
from scapy.layers.inet import _IPOption_HDR

from time import sleep

# 获取网络接口函数
def get_if():
    ifs = get_if_list()
    iface = None  # 默认接口
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

# 定义SwitchTrace数据包格式
class SwitchTrace(Packet):
    fields_desc = [IntField("swid", 0),
                   IntField("qdepth", 0)]

    def extract_padding(self, p):
        return "", p

# 定义IPOption_MRI数据包格式
class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [_IPOption_HDR,
                   FieldLenField("length", None, fmt="B",
                                 length_of="swtraces",
                                 adjust=lambda pkt, l: l * 2 + 4),
                   BitField("loss_bit1", 0, 2),
                   BitField("loss_bit2", 0, 2),
                   BitField("loss_bit3", 0, 2),##############################################################
                   BitField("count", 0, 10),###########################################################
                   PacketListField("swtraces",
                                   [],
                                   SwitchTrace,
                                   count_from=lambda pkt: (pkt.count * 1))]

# 主函数
def main():

    # 检查命令行参数数量
    if len(sys.argv) < 3:
        exit(1)

    # 获取目标地址和网络接口
    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    # 构造数据包
    pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(
        dst=addr, options=IPOption_MRI(count=0,
                                       swtraces=[])) / UDP(
        dport=4321, sport=1234) / sys.argv[2]

    # 发送数据包
    try:
        for i in range(int(sys.argv[3])):
            sendp(pkt, iface=iface)
            sleep(0.1)
    except KeyboardInterrupt:
        raise

# 程序入口
if __name__ == '__main__':
    main()

