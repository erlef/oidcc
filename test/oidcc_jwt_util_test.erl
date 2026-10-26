%% SPDX-FileCopyrightText: 2025 Yannis Weishaupt
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_jwt_util_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("jose/include/jose_jwk.hrl").

verify_claims_test() ->
    % Test exact match claims
    Claims = #{
        <<"iss">> => <<"https://example.com">>,
        <<"sub">> => <<"user123">>,
        <<"aud">> => <<"client456">>
    },

    % Successful exact match
    ?assertEqual(
        ok,
        oidcc_jwt_util:verify_claims(Claims, [{<<"iss">>, <<"https://example.com">>}])
    ),

    % Failed exact match
    ?assertEqual(
        {error, {missing_claim, {<<"iss">>, <<"wrong">>}, Claims}},
        oidcc_jwt_util:verify_claims(Claims, [{<<"iss">>, <<"wrong">>}])
    ),

    % Multiple claims, all match
    ?assertEqual(
        ok,
        oidcc_jwt_util:verify_claims(Claims, [
            {<<"iss">>, <<"https://example.com">>},
            {<<"sub">>, <<"user123">>}
        ])
    ),

    % Multiple claims, one doesn't match
    ?assertEqual(
        {error, {missing_claim, {<<"sub">>, <<"wrong">>}, Claims}},
        oidcc_jwt_util:verify_claims(Claims, [
            {<<"iss">>, <<"https://example.com">>},
            {<<"sub">>, <<"wrong">>}
        ])
    ),

    % Test with non-existent claim
    ?assertEqual(
        {error, {missing_claim, {<<"non-existent">>, <<"value">>}, Claims}},
        oidcc_jwt_util:verify_claims(Claims, [{<<"non-existent">>, <<"value">>}])
    ),

    % Test regex matching
    RegexClaims = #{
        <<"iss">> => <<"https://tenant1.example.com">>
    },

    % Successful regex match
    ?assertEqual(
        ok,
        oidcc_jwt_util:verify_claims(RegexClaims, [
            {<<"iss">>, {regex, <<"^https://tenant\\d+\\.example\\.com$">>}}
        ])
    ),

    % Failed regex match
    ?assertEqual(
        {error, {missing_claim, {<<"iss">>, {regex, <<"^https://other\\..+$">>}}, RegexClaims}},
        oidcc_jwt_util:verify_claims(RegexClaims, [
            {<<"iss">>, {regex, <<"^https://other\\..+$">>}}
        ])
    ),

    % Mix of exact and regex matches
    MixedClaims = #{
        <<"iss">> => <<"https://tenant1.example.com">>,
        <<"sub">> => <<"user123">>
    },

    % All match
    ?assertEqual(
        ok,
        oidcc_jwt_util:verify_claims(MixedClaims, [
            {<<"iss">>, {regex, <<"^https://tenant\\d+\\.example\\.com$">>}},
            {<<"sub">>, <<"user123">>}
        ])
    ),

    % One doesn't match
    ?assertEqual(
        {error, {missing_claim, {<<"sub">>, <<"wrong">>}, MixedClaims}},
        oidcc_jwt_util:verify_claims(MixedClaims, [
            {<<"iss">>, {regex, <<"^https://tenant\\d+\\.example\\.com$">>}},
            {<<"sub">>, <<"wrong">>}
        ])
    ),

    ok.

verify_signature_key_set_kid_test() ->
    Key1 = key_with_kid(<<"kid-1">>),
    Key2 = key_with_kid(<<"kid-2">>),
    OtherKey = jose_jwk:generate_key({ec, <<"P-256">>}),
    KeySet = #jose_jwk{keys = {jose_jwk_set, [Key1, Key2]}},
    Algs = [<<"ES256">>],

    ?assertMatch(
        {ok, _},
        oidcc_jwt_util:verify_signature(sign_with_kid(Key2, <<"kid-2">>), Algs, KeySet)
    ),
    ?assertEqual(
        {error, no_matching_key},
        oidcc_jwt_util:verify_signature(sign_with_kid(OtherKey, <<"kid-1">>), Algs, KeySet)
    ),
    ?assertEqual(
        {error, no_matching_key},
        oidcc_jwt_util:verify_signature(sign_with_kid(OtherKey, <<"kid-2">>), Algs, KeySet)
    ),
    ?assertEqual(
        {error, {no_matching_key_with_kid, <<"kid-3">>}},
        oidcc_jwt_util:verify_signature(sign_with_kid(OtherKey, <<"kid-3">>), Algs, KeySet)
    ),

    MixedKeySet = #jose_jwk{
        keys = {jose_jwk_set, [jose_jwk:generate_key({ec, <<"P-256">>}), Key1]}
    },
    ?assertEqual(
        {error, {no_matching_key_with_kid, <<"kid-3">>}},
        oidcc_jwt_util:verify_signature(sign_with_kid(OtherKey, <<"kid-3">>), Algs, MixedKeySet)
    ).

key_with_kid(Kid) ->
    key_with_kid({ec, <<"P-256">>}, Kid).

key_with_kid(KeyType, Kid) ->
    jose_jwk:merge(jose_jwk:generate_key(KeyType), #{<<"kid">> => Kid}).

sign_with_kid(Key, Kid) ->
    Jws = #{<<"alg">> => <<"ES256">>, <<"kid">> => Kid},
    {_Jws, Token} = jose_jws:compact(jose_jwt:sign(Key, Jws, jose_jwt:from(#{}))),
    Token.

decrypt_and_verify_key_set_kid_test() ->
    Key1 = key_with_kid({rsa, 2048}, <<"kid-1">>),
    Key2 = key_with_kid({rsa, 2048}, <<"kid-2">>),
    OtherKey = jose_jwk:generate_key({rsa, 2048}),
    KeySet = #jose_jwk{keys = {jose_jwk_set, [Key1, Key2]}},
    DecryptAndVerify = fun(Token) ->
        oidcc_jwt_util:decrypt_and_verify(
            Token, KeySet, [<<"RS256">>], [<<"RSA-OAEP">>], [<<"A256GCM">>]
        )
    end,

    ?assertMatch({ok, _}, DecryptAndVerify(encrypt_with_kid(Key2, <<"kid-2">>))),
    ?assertEqual(
        {error, no_matching_key},
        DecryptAndVerify(encrypt_with_kid(OtherKey, <<"kid-1">>))
    ),
    ?assertEqual(
        {error, no_matching_key},
        DecryptAndVerify(encrypt_with_kid(OtherKey, <<"kid-2">>))
    ),
    ?assertEqual(
        {error, {no_matching_key_with_kid, <<"kid-3">>}},
        DecryptAndVerify(encrypt_with_kid(OtherKey, <<"kid-3">>))
    ).

encrypt_with_kid(Key, Kid) ->
    Jwe = #{<<"alg">> => <<"RSA-OAEP">>, <<"enc">> => <<"A256GCM">>, <<"kid">> => Kid},
    {_Jwe, Token} = jose_jwe:compact(jose_jwk:block_encrypt(<<"{}">>, Jwe, Key)),
    Token.
