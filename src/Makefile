CC = gcc
CFLAGS = -std=gnu99 -fno-stack-protector -Wno-deprecated -Wall -Iutil -Iatm -Ibank -Irouter -I.
LIBS = -lcrypto

UNAME := $(shell uname)
ifeq ($(UNAME),Linux)
CFLAGS += -DLINUX -I/usr/local/ssl/include -L/usr/local/ssl/lib
endif

all: bin/atm bin/bank bin/router init

bin/atm : atm/atm-main.c atm/atm.c util/aux_functions.c
	${CC} ${CFLAGS} atm/atm.c atm/atm-main.c util/aux_functions.c -o bin/atm ${LIBS}

bin/bank : bank/bank-main.c bank/bank.c util/hash_table.c util/list.c util/aux_functions.c
	${CC} ${CFLAGS} bank/bank.c bank/bank-main.c util/hash_table.c util/list.c util/aux_functions.c -o bin/bank ${LIBS}

bin/router : router/router-main.c router/router.c util/aux_functions.c
	${CC} ${CFLAGS} router/router.c router/router-main.c util/aux_functions.c -o bin/router ${LIBS}

init : init.c
	${CC} ${CFLAGS} init.c -o init $(LIBS)

test : util/list.c util/list_example.c util/hash_table.c util/hash_table_example.c
	${CC} ${CFLAGS} ${LIBS} util/list.c util/list_example.c -o bin/list-test
	${CC} ${CFLAGS} ${LIBS} util/list.c util/hash_table.c util/hash_table_example.c -o bin/hash-table-test

clean:
	rm -f init
	cd bin && rm -f atm bank router list-test hash-table-test
