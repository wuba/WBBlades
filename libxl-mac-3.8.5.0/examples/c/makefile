CC = gcc
CFLAGS = -I../../include_c -L../../lib -lxl

all: generate extract edit custom format invoice performance

generate: generate.c libxl.dylib
	$(CC) -o generate generate.c $(CFLAGS)

extract: extract.c libxl.dylib
	$(CC) -o extract extract.c $(CFLAGS)

edit: edit.c libxl.dylib
	$(CC) -o edit edit.c $(CFLAGS)

custom: custom.c libxl.dylib
	$(CC) -o custom custom.c $(CFLAGS)

format: format.c libxl.dylib
	$(CC) -o format format.c $(CFLAGS)

invoice: invoice.c libxl.dylib
	$(CC) -o invoice invoice.c $(CFLAGS)

performance: performance.c libxl.dylib
	$(CC) -o performance performance.c $(CFLAGS)

libxl.dylib:
	cp ../../lib/libxl.dylib .

clean:
	rm -f generate extract edit custom format invoice performance *.xls *.xlsx

