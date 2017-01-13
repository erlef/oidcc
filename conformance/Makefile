REBAR = $(shell pwd)/rebar3
APP=oidcc

.PHONY: all ct test clean elvis compile

all: compile

clean:
	$(REBAR) clean
	rm -f rebar.lock
	rm -rf _build

compile:
	$(REBAR) compile

run:
	$(REBAR) run
