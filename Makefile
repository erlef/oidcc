PROJECT = oidcc

DEPS = ejwt base64url uri 
BUILD_DEPS = elvis_mk
DEP_PLUGINS = elvis_mk
TEST_DEPS = meck

dep_uri = git https://github.com/erlware/uri.git 91f6b71 
dep_ejwt = git https://github.com/indigo-dc-tokentranslation/ejwt.git cc9f769
dep_base64url = git https://github.com/dvv/base64url.git v1.0 

# dep_elvis_mk = git https://github.com/inaka/elvis.mk.git 1.0.0
dep_elvis_mk = git https://github.com/inaka/elvis.mk.git 215616a

COVER = 1
include erlang.mk
