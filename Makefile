#
# Makefile for the Linux Traffic Control Unit.
#

sch_onramp-objs	:= flow_queue.o
obj-m += sch_onramp.o
