#complier
CC = gcc
#flags
CFLAGS = -lsqlite3 -lpthread
#objects
OBJECTS = main.o thpool.o
all : nap

thpool.o : thpool.c thpool.h
	$(CC) -c thpool.c

main.o : main.c thpool.c config.h thpool.h
	$(CC) -c main.c

nap : $(OBJECTS)
	$(CC) -o nap $(OBJECTS) $(CFLAGS)

clean :
	rm -rf *o nap
