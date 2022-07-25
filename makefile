CFLAGS=-std=c99

shell: shell.o
        gcc shell.o -o shell

shell.o: shell.c
        gcc --std=c99 -c shell.c
        

