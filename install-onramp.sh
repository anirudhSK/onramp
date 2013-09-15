#! /bin/bash
set -e
make -C /lib/modules/`uname -r`/build SUBDIRS=$PWD modules

set +e
sudo tc qdisc delete dev ingress root
sudo rmmod  ./sch_onramp.ko 
set -e

sudo insmod ./sch_onramp.ko 
sudo tc qdisc add dev ingress root onramp
