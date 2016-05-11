REBAR = $(shell pwd)/rebar3
APP=oidcc

.PHONY: all ct test clean elvis compile 

all: compile

clean:
	$(REBAR) clean

eunit:
	$(REBAR) eunit

ct:
	$(REBAR) ct

elvis:
	$(REBAR) lint

compile:
	$(REBAR) compile

