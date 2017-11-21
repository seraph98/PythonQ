from scapy.all import *
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
    pkg = rdpcap('/home/gavin/NetWorkAna/pcap_package/02.pcap')
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


def get_content(content):
    bc = []
    for i in content:
        t = i[2:]
        d = int(t, 16)
        b = bin(d)[2:]
        b = expand(b)
        bc.append(b)
    return bc

#扩展2进制， 保证有16位
def expand(b):
    l = len(b)
    n = 8 - l
    for i in range(0, n):
        b = '0'+b
    return b


#将以一个字节为单位的二进制转换为16进制字符串(并没什么卵用)
def b2h(bc):
    hs = ''
    for b in bc:
        hs = hs + '\\x'
        i = int(b, 2)
        if i < 16:
            hs = hs + '0'+ hex(i)[2:]
        else:
            hs = hs + hex(i)[2:]
    return hs


#将二进制转换为16进制列表
def b2hls(bc):
    hs = []
    for b in bc:
        i = int(b, 2)
        hs.append(i)
    return hs


def qq_h2d(qq_16_b):
    qq_16 = ''
    for n in qq_16_b:
        if len(n) == 3:
            qq_16 = qq_16 + '0'+n[2:]
        else:
            qq_16 = qq_16 + n[2:]
    qq = int(qq_16, 16)
    return qq


#获得通过手机登录的qq包
def get_qq_info_phone(pkg):
    data = pkg[Raw].load
    if len(data) < 5:
        raise EOFError
    qq_digit_b = data[14:18]
    multiple = 1000
    qq_digit = 0
    for i in qq_digit_b:
        qq_digit = qq_digit + i * multiple
        multiple = multiple / 10
    qq_digit = qq_digit - 4
    max = 18 + qq_digit
    qq_num_b = data[18:int(max)]
    qq_num = qq_num_b.decode('ascii')
    return (qq_num, pkg.sprintf('%IP.src%'), pkg.sprintf('%Ether.src%'), '手机在线')


#获得通过电脑登录的qq包
def get_qq_info_computer(pkg):
    data = pkg[Raw].load
    bts = []
    for b in data:
        bts.append(hex(b))
    qq_16_b = bts[7:11]
    content = bts[11:]
    qq = qq_h2d(qq_16_b)  # 获得10进制的qq号
    bc = get_content(content)  # 获得2进制的内容列表
    hs = b2hls(bc)  # 将2进制内容转成16进制列表
    hsb = bytes(hs)
    # 将qq号加入列表
    return (qq, pkg.sprintf('%IP.src%'), pkg.sprintf('%Ether.src%'), '电脑在线')


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






















