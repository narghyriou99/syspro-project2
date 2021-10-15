MODULE = ./source
INCLUDE = ./include

OBJS	= travelMonitor.o help.o
OBJS1	= monitor.o help.o bloomfilter.o citizen.o hash.o monitorHelp.o skiplist.o virus.o 
SOURCE	= travelMonitor.cpp help.cpp
SOURCE1	= monitor.cpp help.cpp bloomfilter.cpp citizen.cpp hash.cpp monitorHelp.cpp skiplist.cpp virus.cpp
HEADER	= help.h bloomfilter.h citizen.h hash.h monitorHelp.h skiplist.h virus.h
PIPES	= fifo*
OUT	= travelMonitor
OUT1 = monitor
CC	 = g++
FLAGS	 = -g3 -c -Wall -I$(INCLUDE)
LFLAGS	 = 

all: $(OBJS) $(OBJS1)
	$(CC) -g $(OBJS) -o $(OUT) $(LFLAGS)
	$(CC) -g $(OBJS1) -o $(OUT1) $(LFLAGS)

travelMonitor.o: $(MODULE)/travelMonitor.cpp
	$(CC) $(FLAGS) $(MODULE)/travelMonitor.cpp -std=c++11

monitor.o: $(MODULE)/monitor.cpp
	$(CC) $(FLAGS) $(MODULE)/monitor.cpp -std=c++11

monitorHelp.o: $(MODULE)/monitorHelp.cpp
	$(CC) $(FLAGS) $(MODULE)/monitorHelp.cpp -std=c++11

hash.o: $(MODULE)/hash.cpp
	$(CC) $(FLAGS) $(MODULE)/hash.cpp -std=c++11

virus.o: $(MODULE)/virus.cpp
	$(CC) $(FLAGS) $(MODULE)/virus.cpp -std=c++11

citizen.o: $(MODULE)/citizen.cpp
	$(CC) $(FLAGS) $(MODULE)/citizen.cpp -std=c++11

skiplist.o: $(MODULE)/skiplist.cpp
	$(CC) $(FLAGS) $(MODULE)/skiplist.cpp -std=c++11

bloomfilter.o: $(MODULE)/bloomfilter.cpp
	$(CC) $(FLAGS) $(MODULE)/bloomfilter.cpp -std=c++11

help.o: $(MODULE)/help.cpp
	$(CC) $(FLAGS) $(MODULE)/help.cpp -std=c++11

clean:
	rm -f $(OBJS) $(OUT) $(PIPES) \
	$(OBJS1) $(OUT1)

run:
	./travelMonitor -m 5 -b 16 -s 100000 -i ./test

valgrind:
	valgrind ./travelMonitor -m 5 -b 16 -s 100000 -i ./test

count:
	wc ./include/bloomfilter.h ./include/citizen.h ./include/hash.h ./include/help.h ./include/monitorHelp.h ./include/skiplist.h ./include/virus.h ./source/bloomfilter.cpp ./source/citizen.cpp ./source/hash.cpp ./source/help.cpp ./source/monitor.cpp ./source/monitorHelp.cpp ./source/skiplist.cpp ./source/travelMonitor.cpp ./source/virus.cpp