
all: com uart-test

%.o: %.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c -o $@ $^
uart-test: uart-test.o
	$(CC) -o uart-test uart-test.c

com: com.o
	$(CC) -o com com.c

clean:
	rm -f *.o com uart-test
