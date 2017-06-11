import os
import datetime
import sys
import random
import time
NUM = 780


def small_flow_ping(i, host):
    os.system("ping 10.0.0.%d -i 0.01 -c 1000|grep rtt >>%s-LOG"%(i, host))

def small_flow_iperf(i, host):
    os.system("iperf -c 10.0.0.%d -n 10M|grep Mbits >>%s-LOG"%(i, host))



def main():
    host = sys.argv[1]
    os.system(">%s-small"%host)
    os.system(">%s-small"%host)
    for i in range(5):
        if 'h%d'%i == host:
            random.seed(i)
    time.sleep(random.randint(1, 4))
    for _ in range(NUM):
        time.sleep(1)
        i = random.randint(1, 4)
        while 'h%d'%i == host:
            i = random.randint(1, 4)
        start = datetime.datetime.now()
        small_flow_iperf(i, host)
        end = datetime.datetime.now()
        dur = end - start
        os.system('echo %f >>%s-small'%(dur.total_seconds(), host))


if __name__ == '__main__':
    main()
