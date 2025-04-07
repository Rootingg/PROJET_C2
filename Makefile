CC = cc
CFLAGS = -Wall -O2
LDFLAGS = -lcurl -ljson-c
TARGET = main

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c $(LDFLAGS)

clean:
	rm -f $(TARGET)