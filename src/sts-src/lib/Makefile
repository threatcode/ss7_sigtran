# Makefile
BUILDLIBS		:= judy
BUILDPREFIX		:= /opt/local

.PHONY: all

all:
	for lib in $(BUILDLIBS); do pushd $$lib; ./configure --prefix=$(BUILDPREFIX); make; sudo make install; popd; done

