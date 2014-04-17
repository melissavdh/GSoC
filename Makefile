
cipher: cipher.c
	gcc -I /usr/include/ \
    -o cipher cipher.c -L /usr/lib -L /lib -lssl -lcrypto -lcrypt


clean:	
	rm -f cipher
