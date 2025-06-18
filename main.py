import re

from collections import defaultdict, Counter


logfile = "ufwlog.txt"
with open(logfile, "r") as f:
    lines = f.readlines()

log_entries = []
pattern = r"SRC=(\d+\.\d+\.\d+\.\d+).*DST=(\d+\.\d+\.\d+\.\d+).*PROTO=(\w+).*DPT=(\d+)"

for line in lines:
    match = re.search(pattern, line)
    if match:
        src_ip, dst_ip, proto, port = match.groups()
        log_entries.append((src_ip, dst_ip, proto, port))


port_scans = defaultdict(set)
for src, dst, proto, port in log_entries:
    port_scans[src].add(port) # a chaque fois qu'on trouve un port pour la meme ip on l'ajoute

# si il ya plus que 20 port scanner dans une courte periode pur le meme ip alors il peut etre malicieux 
suspicious_ips = [ip for ip, ports in port_scans.items() if len(ports) > 20]
#print("potential port scanners:", suspicious_ips)


attempts = Counter()
for src,dst,proto,port in log_entries:
    attempts[(src,dst)]+=1  #pour  cahque tentative on incremente le compteur  

for (src,dst),count in attempts.items():
    if count> 15: #15 juste pour tester mais dans le cas reel on va metere 50 par exemple
        print(f"{src} trierd to connect to {dst}, {count} times")

