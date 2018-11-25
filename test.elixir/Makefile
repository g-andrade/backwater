MIX = mix 

.PHONY: all test

all: deps test

clean:
	rm -rf _build deps

deps:
	$(MIX) deps.get

test: deps
	$(MIX) test
