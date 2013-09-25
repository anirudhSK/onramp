#
# Makefile for the Linux Traffic Control Unit.
#

onramp-objs	:= flow_queue.o sch_onramp.o
obj-m += onramp.o
