#/bin/sh

#1: Flush and delete all previously defined rules and chains
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -t mangle -F
sudo iptables -t raw -F
sudo iptables -X

#2: Write a rule that only accepts packets that originate from f1.com
sudo iptables -A INPUT -s 67.199.248.13 -j ACCEPT

#3: For all outgoing packets, change their source IP address to your own machine’s IP address (Hint: Refer to the MASQUERADE target in the nat table).
sudo iptables -t nat -A POSTROUTING -j MASQUERADE

#4: 
sudo iptables -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -m limit --limit 1/s -j ACCEPT

#5:
sudo iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 500 -m state --state NEW -j ACCEPT

#6:
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

#7:
sudo iptables -t nat -A PREROUTING -p tcp --dport 8888 -j DNAT --to-destination :25565

#8:
sudo iptables -A OUTPUT -p tcp --dport 22 -d engineering.purdue.edu -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p tcp --sport 22 -s engineering.purdue.edu -m state --state ESTABLISHED,RELATED -j ACCEPT

#9:
sudo iptables -A INPUT -j DROP
sudo iptables -A OUTPUT -j DROP
