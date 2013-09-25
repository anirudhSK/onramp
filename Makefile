#
# Makefile for the Linux Traffic Control Unit.
#

onramp-y	:= flow_queue.o sch_onramp.o onramp_rb_tree.o
obj-m += onramp.o
