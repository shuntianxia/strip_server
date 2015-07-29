#DIR_SRC := ../src

CC := gcc
#VPATH := ../src
#LIBS := -lrpm -lrpmio
override CFLAGS := -Wall -g #-I$(DIR_SRC)

objects := net_interface.o work_queue.o db_interface.o daemon.o smart_strip.o

main: $(objects)
	$(CC) $(CFLAGS) -o smart_strip $(objects) -lpthread -L/usr/lib/mysql/ -lmysqlclient
	

.PHONY: clean
clean:
	-rm $(objects) smart_strip
