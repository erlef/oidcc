REBAR = $(shell pwd)/rebar3
APP=oidcc

.PHONY: all ct test clean elvis compile basic_client

all: compile

clean:
	$(REBAR) clean

eunit:
	$(REBAR) do eunit, cover -v
	cp _build/test/cover/eunit.coverdata .

ct:
	$(REBAR) do ct, cover -v
	cp _build/test/cover/ct.coverdata .

tests:
	$(REBAR) do lint, eunit, ct, cover -v

elvis:
	$(REBAR) lint

compile:
	$(REBAR) compile
