import re

from collections import defaultdict

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

print(log_entries[:])  # test 

