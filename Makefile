DOWNLOAD=$(shell cat .git/config | grep url | sed 's/.*=//;s/[Zz]edex/Zeditty/')
CFLAGS += -IZeditty/include -std=gnu99 -Wall
LDFLAGS += -LZeditty/lib -lzeditty
all:
	sh -c 'which sdcc || (echo Please install: sdcc && exit 1)'
	if [ ! -d "Zeditty" ]; then git clone $(DOWNLOAD); fi
	make -C Zeditty/
	$(CC) $(CFLAGS) src/zedex.c -o bin/zedex $(LDFLAGS)
	sdasz80 -o bin/crt0.rel src/crt0.s


