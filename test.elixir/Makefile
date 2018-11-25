MIX = mix 

.PHONY: all test

all: deps test

deps:
	$(MIX) deps.get

test: deps
	$(MIX) test
