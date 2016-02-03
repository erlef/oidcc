PROJECT = oidcc

DEPS = ejwt base64url ehtc

dep_ehtc = git https://github.com/indigo-dc-tokentranslation/ehtc.git master
dep_ejwt = git https://github.com/indigo-dc-tokentranslation/ejwt.git master
dep_base64url = git https://github.com/indigo-dc-tokentranslation/base64url.git master
include erlang.mk
