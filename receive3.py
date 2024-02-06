
#!/usr/bin/env python
import sys
import struct
import time 
# 导入scapy库，用于捕获和分析数据包
from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

import csv  # 导入CSV模块###########################################################

# 初始化全局变量

Total_Loss = 0.0
Total_Packet = 0.0
Total_Lost_Packet = 0.0
Total_Loss_Bit1 = 0
Total_Loss_Bit2 = 0
Total_Loss_Bit3 = 0###################################
Packet_Sequence = 0  # 在代码的全局变量部分加入这一行#######################

# 获取网络接口函数
def get_if():
    ifs=get_if_list()
    print("get_if_list():", ifs)########################################
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            print("Found interface:", iface)  # 打印找到的接口
            break;
    if not iface:
        print ("Cannot find eth0 interface")
        exit(1)
    return iface
# 定义SwitchTrace数据包格式
class SwitchTrace(Packet):
    fields_desc = [ IntField("swid", 0),
                  IntField("qdepth", 0)]
    def extract_padding(self, p):
                return "", p
# 定义IPOption_INT数据包格式
class IPOption_INT(IPOption):
    name = "INTLoss"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swtraces",
                                  adjust=lambda pkt,l:l*2+4),
                    BitField("loss_bit1", 0, 2),
		    BitField("loss_bit2", 0, 2),
		    BitField("loss_bit3", 0, 2),###########################################################
                    BitField("count", 0, 10),#######################################################
                    PacketListField("swtraces",
                                   [],
                                   SwitchTrace,
                                   count_from=lambda pkt:(pkt.count*1)) ]
# 初始化CSV文件###################################
def init_csv(filename):
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['Packet Number', 'Switch ID', 'Queue Depth']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
def init_csv_loss(filename):
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['Packet Number', 'Time', 'Loss Rate']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()


# 将遥测数据写入CSV文件##########################################################
def write_to_csv(filename, packet_number, swid, qdepth):
    with open(filename, 'a', newline='') as csvfile:#######################
        fieldnames = ['Packet Number', 'Switch ID', 'Queue Depth']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writerow({'Packet Number': packet_number, 'Switch ID': swid, 'Queue Depth': qdepth})
#存储丢包信息##########################################################
def write_loss_to_csv(filename, packet_number, time, loss_rate):
    with open(filename, 'a', newline='') as csvfile:##################################
        fieldnames = ['Packet Number', 'Time', 'Loss Rate']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writerow({'Packet Number': packet_number, 'Time': time, 'Loss Rate': loss_rate})

        
# 处理捕获的数据包
def handle_pkt(pkt):
    global Total_Loss
    global Total_Packet
    global Total_Lost_Packet
    global Total_Loss_Bit1
    global Total_Loss_Bit2
    global Total_Loss_Bit3#########################################################
    if Total_Packet%100 == 0:
        print("[Ordinary Report]")
        print("  - Event: Receive the #" + str(int(Total_Packet)) +" telemetry packet!")
        print("pkt[IP].options:" + str(pkt[IP].options))
        #print("  - Telemetry Result Stream: " + str(IPOption_INT(str(pkt[IP].options))) + "\n")
        print("  - Telemetry Result Stream:")
        for option in pkt[IP].options:
            if isinstance(option, IPOption_INT):
        # 打印或处理IPOption_INT字段
                print("    Loss Bit 1:", option.loss_bit1)
                print("    Loss Bit 2:", option.loss_bit2)
                print("    Loss Bit 3:", option.loss_bit3)###############################################
                print("    Count:", option.count)
        
                for trace in option.swtraces:
                    print("    SwitchTrace SWID:", trace.swid)
                    print("    SwitchTrace QDepth:", trace.qdepth)
        print("\n")
        #pkt.show2()
    for option in pkt[IP].options:
        if isinstance(option, IPOption_INT):
            loss_bit1 = option.loss_bit1
            break

    #if loss_bit1 is not None:
        #print("Loss Bit 1:", loss_bit1)
    #else:
        #print("IPOption_INT not found in packet options!")
    for option in pkt[IP].options:
        if isinstance(option, IPOption_INT):
            loss_bit2 = option.loss_bit2
            break
    #############################################
    for option in pkt[IP].options:
        if isinstance(option, IPOption_INT):
            loss_bit3 = option.loss_bit3
            break
    ##########################################################################
    for option in pkt[IP].options:
        if isinstance(option, IPOption_INT):
            # ... [其他代码]
            for trace in option.swtraces:
                # 根据swid选择CSV文件名
                filename = f'telemetry_data_switch_{trace.swid}.csv'
                # 写入数据到指定的CSV文件
                write_to_csv(filename, Total_Packet+1, trace.swid, trace.qdepth)
    ###########################################################################
    #if loss_bit2 is not None:
        #print("Loss Bit 2:", loss_bit2)
    #else:
        #print("IPOption_INT not found in packet options!")
    #loss_bit1 = str(IPOption_INT(str(pkt[IP].options)))[77:78]
    #loss_bit2 = str(IPOption_INT(str(pkt[IP].options)))[90:91]
    
    Total_Packet = Total_Packet + 1###############################
    
    if (int(loss_bit1) != Total_Loss_Bit1 or int(loss_bit3) != Total_Loss_Bit3):##################################################
        current_time = time.strftime('%H:%M:%S', time.localtime(time.time()))##########################################
        Total_Lost_Packet = Total_Lost_Packet + 1#################################
        Total_Packet = Total_Packet + 1##################################################################################################################################################################
        if (int(loss_bit3) != Total_Loss_Bit3):
            write_loss_to_csv('loss_data_switch_3.csv', Total_Packet, current_time, 100 * Total_Lost_Packet / Total_Packet)###############################
            print("[Warning]")
            print("  - Packet Loss Happened!" )
            print("[Detail]") 
            print("  - Time: " + time.strftime('%H:%M:%S',time.localtime(time.time())))
            print("  - Location: Switch #3")
        if (int(loss_bit1) != Total_Loss_Bit1): 
            write_loss_to_csv('loss_data_switch_1.csv', Total_Packet, current_time, 100 * Total_Lost_Packet / Total_Packet)################################
            print("[Warning]")
            print("  - Packet Loss Happened!" )
            print("[Detail]")
            print("  - Time: " + time.strftime('%H:%M:%S',time.localtime(time.time())))
            print("  - Location: Switch #1")
        
        print("[More Information]") 
        print("  - Cumulative number of Telemetry Reports: " + str(int(Total_Packet))) 
        print("  - Cumulative number of Lost Packets: " + str(int(Total_Lost_Packet))) 
        print("  - Current Loss Rate: " + str(100*Total_Lost_Packet/Total_Packet)+ "\n")
    
        
    Total_Loss_Bit1 = int(loss_bit1) + 1
    Total_Loss_Bit2 = int(loss_bit2) + 1
    Total_Loss_Bit3 = int(loss_bit3) + 1##############################

    if ( Total_Loss_Bit1 > 3):
        Total_Loss_Bit1 = 0
    if ( Total_Loss_Bit2 > 3):
        Total_Loss_Bit2 = 0
    if ( Total_Loss_Bit3 > 3):###############################################
        Total_Loss_Bit3 = 0

    sys.stdout.flush()




def main():
    for i in range(1, 4):
        init_csv(f'telemetry_data_switch_{i}.csv') # 初始化CSV文件#######################################
        init_csv_loss(f'loss_data_switch_{i}.csv') # 初始化CSV文件#######################################
    iface = get_if()
    #iface = 'h2-eth0'###############################################################

    print("\n")
    print("      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print("      +    LossSight is Ready!    +")
    print("      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print("\n")





    sys.stdout.flush()
    # 开始捕获满足条件的数据包
    sniff(filter="udp and port 4321", iface = iface,
          prn = lambda x: handle_pkt(x))




# 程序入口
if __name__ == '__main__':
    main()
