obj-m += mbox.o

KDIR =/usr/src/linux-4.0

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	rm -rf *.o *.ko *.mod.* *.symvers *.order
