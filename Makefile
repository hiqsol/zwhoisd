all: zwhoisd

zwhoisd: zwhoisd.c
	cc -O -o zwhoisd -I/usr/include -I/usr/local/include -L/usr/lib -L/usr/local/lib zwhoisd.c
	strip zwhoisd

