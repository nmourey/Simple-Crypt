all:
	gcc -ggdb simplecrypt.c -o sc
clean:
	rm sc
install:
	cp sc ${HOME}/bin
strip:
	strip sc
