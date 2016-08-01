ifeq ($(origin domain), undefined)
$(error make domain=foo.bar.com prefixes="www smtp derp")
endif

SRC ?= ..

%/:
	mkdir $@
%/key.temp: | %/
	
%/pub.temp: %/key
	
%/csr.temp: %/key
	python $(SRC)/make_csr.py $*/key $(domain) $(prefixes) >$@
%/cert.temp: user/key user/pub %/csr
	python2 $(SRC)/sign_csr.py --public-key user/pub --private-key user/key $*/csr > $@

%: %.temp
	mv $< $@

OUT ?= /etc/letsencrypt/
$(OUT)$(domain)/cert: $(OUT)$(domain)/cert.temp

.PRECIOUS: %/pub %/key %/cert %/csr
.INTERMEDIATE: %/%.temp
.DELETE_ON_ERROR:
