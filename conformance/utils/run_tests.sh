#!/bin/bash
BIN="./_build/default/rel/conformance/bin/conformance"
echo -n "starting application ..."
$BIN start
sleep 2
echo "done"
TESTS="rp-response_type-code rp-scope-userinfo-claims&scp=all rp-scope-userinfo-claims&scp=profile rp-scope-userinfo-claims&scp=email rp-scope-userinfo-claims&scp=address rp-scope-userinfo-claims&scp=phone rp-nonce-invalid rp-token_endpoint-client_secret_basic rp-id_token-aud rp-id_token-kid-absent-single-jwks rp-id_token-sig-none rp-id_token-issuer-mismatch rp-id_token-kid-absent-multiple-jwks rp-id_token-bad-sig-rs256 rp-id_token-iat rp-id_token-sig-rs256 rp-id_token-sub rp-userinfo-bad-sub-claim rp-userinfo-bearer-header rp-discovery-jwks_uri-keys rp-discovery-issuer-not-matching-config rp-discovery-openid-configuration rp-key-rotation-op-sign-key rp-userinfo-sig"
HOST="https://localhost:8080/test/?id="
echo -n "running tests "
for TEST in $TESTS
do
    echo -n "."
    curl -s -S --insecure -L "$HOST$TEST" > /dev/null

done
echo " done"
$BIN stop
cat /tmp/oidcc_rp_conformance/summary.log
