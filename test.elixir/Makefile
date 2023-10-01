MIX = mix 

.PHONY: all test

all: deps test

clean:
	rm -rf _build deps mix.lock

deps: mix.exs ../rebar.config
	$(MIX) deps.get; \
	$(MIX) deps.clean --unlock --unused; \
	$(MIX) deps.update --all

test: deps
	$(MIX) test
