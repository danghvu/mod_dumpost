all: mod_dumpost.c
	apxs2 -c mod_dumpost.c

install: all
	sudo apxs2 -i -a -n dumpost mod_dumpost.la
	sudo service apache2 restart

clean:
	rm mod_dumpost.l*
	rm mod_dumpost.s*
