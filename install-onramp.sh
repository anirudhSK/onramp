#! /bin/bash
set -e
make -C /lib/modules/`uname -r`/build SUBDIRS=$PWD clean
make -C /lib/modules/`uname -r`/build SUBDIRS=$PWD modules

set +e
sudo tc qdisc delete dev ingress root
sudo rmmod  ./onramp.ko
set -e

sudo insmod ./onramp.ko
sudo ifconfig ingress 10.0.0.1
set -x; for i in `echo "2 3 4 5 6 7 8 9"`; do sudo arp -s 10.0.0.$i $i$i:$i$i:$i$i:$i$i:$i$i:$i$i ; done; set +x
sudo tc qdisc add dev ingress root onramp
