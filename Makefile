# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the linux ext4-filesystem routines.
#

obj-m += open_syscall_module.o

open_syscall_module-y	:= super.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

open_syscall_module-y	+= fs/open.o
open_syscall_module-y	+= fs/file.o
open_syscall_module-y	+= fs/namei.o

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
