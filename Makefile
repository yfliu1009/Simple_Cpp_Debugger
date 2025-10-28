sdb: sdb.c
	gcc -o sdb sdb.c -lcapstone

clean:
	rm -f sdb