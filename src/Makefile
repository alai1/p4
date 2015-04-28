CC = gcc
CFLAGS = -fno-stack-protector -Wall -Iutil -Iatm -Ibank -Irouter -I.
LIBS = -lcrypto

UNAME := $(shell uname)
ifeq ($(UNAME),Linux)
CFLAGS += -DLINUX -I/usr/local/ssl/include -L/usr/local/ssl/lib
endif

all: bin/atm bin/bank bin/router bin

bin/atm : atm/atm-main.c atm/atm.c
	${CC} ${CFLAGS} ${LIBS} atm/atm.c atm/atm-main.c -o bin/atm

bin/bank : bank/bank-main.c bank/bank.c
	${CC} ${CFLAGS} ${LIBS} bank/bank.c bank/bank-main.c -o bin/bank

bin/router : router/router-main.c router/router.c
	${CC} ${CFLAGS} ${LIBS} router/router.c router/router-main.c -o bin/router

bin : init.c
	${CC} ${CFLAGS} init.c -o init $(LIBS)

test : util/list.c util/list_example.c util/hash_table.c util/hash_table_example.c
	${CC} ${CFLAGS} ${LIBS} util/list.c util/list_example.c -o bin/list-test
	${CC} ${CFLAGS} ${LIBS} util/list.c util/hash_table.c util/hash_table_example.c -o bin/hash-table-test

clean:
	cd bin && rm -f atm bank router list-test hash-table-test
