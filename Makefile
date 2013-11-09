APXS = apxs

all: mod_dumpost.c mod_dumpost.h
	$(APXS) -Wc,-Wall -c mod_dumpost.c

debug: mod_dumpost.c mod_dumpost.h
	$(APXS) -Wc,-g3 -c mod_dumpost.c

install: all
	sudo $(APXS) -i -a -n dumpost mod_dumpost.la;\
	echo Now restart your apache

clean:
	rm mod_dumpost.l*
	rm mod_dumpost.s*
