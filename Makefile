all: mod_dumpost.c mod_dumpost.h
	apxs2 -Wc,-Wall -c mod_dumpost.c

debug: mod_dumpost.c mod_dumpost.h
	apxs2 -Wc,-g3 -c mod_dumpost.c

install: all
	sudo apxs2 -i -a -n dumpost mod_dumpost.la
	sudo service apache2 restart

clean:
	rm mod_dumpost.l*
	rm mod_dumpost.s*
