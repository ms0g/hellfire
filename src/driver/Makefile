MODULE=hellfire
PWD := $(shell pwd)
KERNELRELEASE := $(shell uname -r)
KDIR := /lib/modules/${KERNELRELEASE}/build
MDIR := /lib/modules/${KERNELRELEASE}
ccflags-y := -std=gnu99
obj-m := ${MODULE}.o
${MODULE}-objs := ../netfilter/hooks.o ../netfilter/policy_table.o hellfire_core.o

all:
	make -C ${KDIR} M=${PWD} modules
	rm -r -f *.mod.c .*.cmd *.symvers *.o
install:
	sudo insmod hellfire.ko
remove:
	sudo rmmod hellfire.ko
clean:
	make -C  ${KDIR} M=${PWD} clean