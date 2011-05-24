all: of-extractor

of-extractor: of-extractor.o util.o ofpbuf.o hash.o flow.o chain.o table-linear.o
	libtool --mode=link gcc -g -O -o of-extractor -lpcap \
	-lpthread util.o  ofpbuf.o flow.o \
	of-extractor.o -lm 
#libhashish/lib/libhashish.a

of-extractor.o: of-extractor.c
	gcc -Ilibhashish/include/ -g -c of-extractor.c

util.o: util.c util.h
	gcc -Ilibhashish/include/ -g -c util.c

ofpbuf.o: ofpbuf.c ofpbuf.h
	gcc -Ilibhashish/include/ -g -c ofpbuf.c

hash.o: hash.c hash.h
	gcc -Ilibhashish/include/ -g -c hash.c

flow.o: flow.c flow.h
	gcc -Ilibhashish/include/ -g -c flow.c

chain.o: chain.c chain.h
	gcc -Ilibhashish/include/ -g -c chain.c

table-linear.o: table-linear.c table.h
	gcc -Ilibhashish/include/ -g -c table-linear.c

clean:
	rm -rf *~ *.o of-extractor .libs/

debug:
	libtool --mode=execute gdb of-extractor