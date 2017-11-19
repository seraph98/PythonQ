import logging

from scapy.layers.inet import ICMP, IP, TCP

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

def  ping_one(host):
    ip_id=RandShort()
    icmp_id=RandShort()
    icmp_seq=RandShort()
    packet=IP(dst=host,ttl=64,id=ip_id)/ICMP(id=icmp_id,seq=icmp_seq)/b'ylp'
    ping=sr1(packet,timeout=2,verbose=False)
    if ping:
            return 0
    else:
            return -1
def syn_scan(hostname,lport,hport):
    ping_res=ping_one(hostname)
    print('完成ping')
    if ping_res==-1:
            print('设备'+hostname+'不可达')
    else:
            print('设备可达')
            syn=IP(dst=hostname)/TCP(dport=(int(lport),int(hport)),flags=2)
            result_raw=sr(syn,timeout=1,verbose=False)
            print('发包结束')
            #取出收到结果的数据包，做成一个清单
            result_list=result_raw[0].res
            for i in range(len(result_list)):
                #判断清单的第i个回复的接受到的数据包，并判断是否有TCP字段
                if(result_list[i][1].haslayer(TCP)):
                    #得到TCP字段的头部信息
                    TCP_Fields=result_list[i][1].getlayer(TCP).fields
                    #判断头部信息中的flags标志是否为18(syn+ack)
                    if TCP_Fields['flags']==18:
                            print('端口号: '+str(TCP_Fields['sport'])+' is Open!!!')
            print('OVER')



if __name__=='__main__':
        # host=input('请输入扫描主机的IP地址:')
        # port_low=input('请输入扫描端口的最低端口号')
        # port_high=input('请输入扫描端口的最高端口号')
        syn_scan('192.168.85.132','1','65535')