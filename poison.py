from scapy.all import *
from util import *
import csv


def get_qq_list():
    dt = {}
    with open('QQmail.csv', encoding='gbk') as f:
        csv_reader = csv.reader(f)
        for row in csv_reader:
            if row[2] == '电子邮件':
                continue
            dt[row[2][:-7]] = row[0]
    return dt


def main(qq_list):
    pkg = rdpcap('/home/gavin/NetWorkAna/pcap_package/21.pcapng')
    for p in pkg:
        # if p[]
        if p.sprintf('%Ether.src%') == '78:0c:b8:37:06:86':
            continue
        try:
            if p.sprintf('%IP.dst%') == '182.254.10.38':
                qq_info = get_qq_info_phone(p)
            else:
                qq_info = get_qq_info_computer(p)
        except Exception as e:
            continue
        if qq_info not in qq_list:
            qq_list.append(qq_info)
    return qq_list















if __name__ == '__main__':
    qq_list = []
    qq_classmate = get_qq_list()
    main(qq_list)
    for qq_info in qq_list:
        qq_num = str(qq_info[0])
        if qq_classmate.get(qq_num, False):
            print(qq_num+':'+qq_classmate[qq_num]+"; Ip地址:"+qq_info[1]+"; mac地址-->"+qq_info[2]+'; '+qq_info[3])
        else:
            print(qq_num)






















