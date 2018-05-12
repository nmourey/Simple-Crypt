all:
	gcc simplecrypt.c -o sc
	gcc -ggdb simplecrypt.c -o sc-debug
clean:
	rm sc sc-debug
install:
	cp sc ${HOME}/bin
strip:
	strip sc
