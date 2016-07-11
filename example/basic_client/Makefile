REBAR = $(shell pwd)/rebar3
APP=oidcc

.PHONY: all ct test clean elvis compile 

all: compile

clean:
	$(REBAR) clean

compile:
	$(REBAR) compile

run:
	$(REBAR) run

oidcc_dev:
	cp -r ../../src/* _build/default/lib/oidcc/src
	rm -rf _build/default/lib/oidcc/ebin
