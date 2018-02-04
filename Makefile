REBAR3_URL=https://s3.amazonaws.com/rebar3/rebar3

ifeq ($(wildcard rebar3),rebar3)
	REBAR3 = $(CURDIR)/rebar3
endif

REBAR3 ?= $(shell test -e `which rebar3` 2>/dev/null && which rebar3 || echo "./rebar3")

ifeq ($(REBAR3),)
	REBAR3 = $(CURDIR)/rebar3
endif

TEST_PROFILE ?= test

.PHONY: all build clean check dialyzer xref run test cover console travis doc publish

all: build

build: $(REBAR3)
	@$(REBAR3) compile

$(REBAR3):
	wget $(REBAR3_URL) || curl -Lo rebar3 $(REBAR3_URL)
	@chmod a+x rebar3

clean:
	@$(REBAR3) clean

check: dialyzer xref

dialyzer:
	@$(REBAR3) as development dialyzer

xref:
	@$(REBAR3) as development xref

test:
	@$(REBAR3) as $(TEST_PROFILE) eunit, ct
	@if [ "$(TEST_PROFILE)" != "travis_test" ]; then \
		make -C test.elixir; \
		rm -rf ebin; \
	fi

cover: test
	@$(REBAR3) as test cover

console:
	@$(REBAR3) as development shell --apps backwater

travis: TEST_PROFILE = travis_test
travis: test

doc: build
	./scripts/hackish_make_docs.sh

publish:
	@$(REBAR3) as publication hex publish
