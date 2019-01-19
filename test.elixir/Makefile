MIX = mix 

.PHONY: all test

all: deps test

clean:
	rm -rf _build deps mix.lock

deps: mix.exs ../rebar.config
	$(MIX) deps.get

test: deps
	$(MIX) test
