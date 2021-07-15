
CFLAGS = -std=c++11 -g -I ./include -L ./lib -L/lib -L/usr/lib -L/usr/local/lib 
LDFLAGS = -lpthread -leXosip2 -losip2 -losipparser2 -Wl,-rpath,./lib

BIN = demo

all:
	g++ -o $(BIN) demo.cpp $(CFLAGS) $(LDFLAGS)

clean:
	rm $(BIN)
