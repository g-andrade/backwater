REBAR_DIALYZER_PROFILE ?= ranch2
REBAR_SHELL_PROFILE ?= shell
REBAR_TEST_PROFILE ?= test

all: build
.PHONY: all

build:
	@rebar3 compile
.PHONY: build

clean:
	@rebar3 clean
.PHONY: clean

check: xref dialyzer
.PHONY: check
.NOTPARALLEL: check

xref:
	@rebar3 xref
.PHONY: xref

dialyzer:
	@rebar3 as $(REBAR_DIALYZER_PROFILE) dialyzer
.PHONY: dialyzer

test: erlang-test elixir-test
.PHONY: test
.NOTPARALLEL: test

erlang-test:
	@rebar3 as $(REBAR_TEST_PROFILE) eunit, ct, cover
.PHONY: erlang-test

elixir-test:
	make -C test.elixir
.PHONY: elixir-test

shell: export ERL_FLAGS = +pc unicode
shell:
	@rebar3 as $(REBAR_SHELL_PROFILE) shell
.PHONY: shell

doc:
	@rebar3 ex_doc
.PHONY: doc

publish:
	@rebar3 hex publish
.PHONY: publish
