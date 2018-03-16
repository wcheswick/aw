CFLAGS+=-g -Wall -Wno-unused

OBJS=main.o util.o fbsd.o # sensor.o tunnel.o pkt.o

all::	aw

aw:	${OBJS}
	${CC} ${CFLAGS} ${OBJS} -lpcap -o $@

clean::	
	rm -f *.o *.core aw

${OBJS}:	aw.h
