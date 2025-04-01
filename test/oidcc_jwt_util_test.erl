-module(oidcc_jwt_util_test).

-include_lib("eunit/include/eunit.hrl").

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