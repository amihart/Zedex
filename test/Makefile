DOWNLOAD=$(shell cat .git/config | grep url | sed 's/.*=//;s/Zedex/Zeditty/')
CFLAGS += -IZeditty/include
LDFLAGS += -LZeditty/lib -lzeditty
all:
	sh -c 'which sdcc || (echo Please install: sdcc && exit 1)'
	sh -c 'which srec_cat || (echo Please install: srecord && exit 1)'

	sdcc ../bin/crt0.rel -mz80 --no-std-crt0 hello_syscall.c -o ~tmp.hex -I../include
	srec_cat ~tmp.hex -Intel -Output -Binary > hello_syscall.z80
	rm -f ~tmp*

	sdcc ../bin/crt0.rel -mz80 --no-std-crt0 hello_stdio.c -o ~tmp.hex -I../include
	srec_cat ~tmp.hex -Intel -Output -Binary > hello_stdio.z80
	rm -f ~tmp*

	sdcc ../bin/crt0.rel -mz80 --no-std-crt0 arguments.c -o ~tmp.hex -I../include
	srec_cat ~tmp.hex -Intel -Output -Binary > arguments.z80
	rm -f ~tmp*

#	sdasz80 -o crt0.rel crt0.s
#	sdcc crt0.rel -mz80 --no-std-crt0 hello.c -o ~tmp.hex -Iinclude
#	@echo "Running test..."
#	./interpret hello.z80 fish boi
clean:
	rm -f interpret crt0.rel hello.z80
