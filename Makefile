all:
	gcc -W aes.c sha256.c client.c -o client -lgmp
clean:
	rm client
measandwich:
	gcc -g -W aes.c sha256.c client.c -o client -lgmp
