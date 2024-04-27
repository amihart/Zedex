DOWNLOAD=$(shell cat .git/config | grep url | sed 's/.*=//;s/[Zz]edex/Zeditty/')
CFLAGS += -IZeditty/include -std=gnu99 -Wall
LDFLAGS += -LZeditty/lib -lzeditty
all:
	sh -c 'which sdcc || (echo Please install: sdcc && exit 1)'
	if [ ! -d "Zeditty" ]; then git clone $(DOWNLOAD); fi
	make -C Zeditty/

	$(CC) -S src/call_table.c -o src/call_table.s
	sh -c 'echo `cat src/call_table.s | grep -i '\.size' | grep 'CALL_TABLE' | sed 's/.*,//' | xargs` / 24 | bc > .call_table_size'
	$(CC) $(CFLAGS) -c src/call_table.c -o src/call_table.o
	$(CC) $(CFLAGS) -c src/zedex.c -o src/zedex.o -DCALL_TABLE_SIZE=$(shell cat .call_table_size)
	$(CC) $(CFLAGS) -o bin/zedex src/call_table.o src/zedex.o $(LDFLAGS)

	sdasz80 -o bin/crt0.rel src/crt0.s
	make -C test


