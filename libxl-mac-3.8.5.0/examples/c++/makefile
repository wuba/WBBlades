CC = g++
CFLAGS = -I../../include_cpp -L../../lib -lxl

all: write read edit custom format invoice performance

write: write.cpp libxl.dylib
	$(CC) -o write write.cpp $(CFLAGS)

read: read.cpp libxl.dylib
	$(CC) -o read read.cpp $(CFLAGS)

edit: edit.cpp libxl.dylib
	$(CC) -o edit edit.cpp $(CFLAGS)

custom: custom.cpp libxl.dylib
	$(CC) -o custom custom.cpp $(CFLAGS)

format: format.cpp libxl.dylib
	$(CC) -o format format.cpp $(CFLAGS)

invoice: invoice.cpp libxl.dylib
	$(CC) -o invoice invoice.cpp $(CFLAGS)

performance: performance.cpp libxl.dylib
	$(CC) -o performance performance.cpp $(CFLAGS)

libxl.dylib:
	cp ../../lib/libxl.dylib .

clean:
	rm -f write read edit custom format invoice performance *.xls *.xlsx

