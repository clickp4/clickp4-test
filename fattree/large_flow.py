import os
import datetime
import sys
import random
import time
NUM = 40


def large_flow(host, i):
    os.system("iperf -c 10.0.0.%d -n 500M|grep Mbits >>%s-large"%(i, host))


def main():
    host = sys.argv[1]
    os.system(">%s-large"%host)
    time.sleep(random.randint(1, 4))
    for i in range(5):
        if 'h%d'%i == host:
            random.seed(i)
    for _ in range(NUM):
        time.sleep(5)
        i = random.randint(1, 4)
        while 'h%d'%i == host:
            i = random.randint(1, 4)
        large_flow(host, i)


if __name__ == '__main__':
    main()
