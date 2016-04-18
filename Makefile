PROJECT = oidcc

DEPS = ejwt uri gun
BUILD_DEPS = elvis_mk
DEP_PLUGINS = elvis_mk
TEST_DEPS = meck

dep_gun = git https://github.com/ninenines/gun.git d88f367
dep_uri = git https://github.com/erlware/uri.git 91f6b71 
dep_ejwt = git https://github.com/indigo-dc/ejwt.git ba89eee
dep_meck = git https://github.com/eproxus/meck 0.8.4

# dep_elvis_mk = git https://github.com/inaka/elvis.mk.git 1.0.0
dep_elvis_mk = git https://github.com/inaka/elvis.mk.git 215616a

COVER = 1
include erlang.mk
