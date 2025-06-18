import re,csv

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

# si il ya plus que 20 port scanner dans une courte periode pur le meme ip alors il peut etre un scanneur de port 
suspicious_ips = [ip for ip, ports in port_scans.items() if len(ports) > 20]
#print("potential port scanners:", suspicious_ips)


attempts = Counter()
for src,dst,proto,port in log_entries:
    attempts[(src,dst)]+=1  #pour  cahque tentative on incremente le compteur  

for (src,dst),count in attempts.items():
    if count> 15: #15 juste pour tester mais dans le cas reel on va metere 50 par exemple
        print(f"{src} trierd to connect to {dst}, {count} times")

#ecrire un rapport et un fichier csv
with open("report.txt", "w") as f:
    f.write("Suspicious IPs:\n")
    for ip in suspicious_ips:
        f.write(f"{ip}\n")

with open("summary.csv", "w", newline='') as f:
    writer = csv.writer(f)
    writer.writerow(["IP", "Unique Ports"])
    for ip, ports in port_scans.items():
        if len(ports) > 20:
            writer.writerow([ip, len(ports)])



#envoyer un email pour les ip supicieux
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart



def email_alert (suspicious_ips,sender_email,receiver_email,sender_password):
    if not suspicious_ips:
        return
     
    objet = "security alert: suspicious ip detected"
    body = "the following ip triggered a security alert :\n\n"

    for ip in suspicious_ips:
        body += f"{ip}\n"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = objet
         
    msg.attach(MIMEText(body, 'plain'))

    try:
        # connection au serveur smtp
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)

        # envoyer l'email
        server.send_message(msg)
        print("[+] alert email envoyer avec succes") 
        server.quit()
    except Exception as e:
        print("[-] echoux a envoyer l'email : ", str(e))


#pour appeler la fonction email_alert enter les parametre ici
#email_alert(
 #   suspicious_ips,
  #  sender_email = "",
   # receiver_email = "",
    #sender_password = ""
#)