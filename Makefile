all: zwhoisd

zwhoisd: zwhoisd.c lookup3.c
	cc -O -o zwhoisd -I/usr/include -I/usr/local/include -L/usr/lib -L/usr/local/lib zwhoisd.c lookup3.c
	strip zwhoisd

