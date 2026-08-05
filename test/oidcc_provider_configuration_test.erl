%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_provider_configuration_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("oidcc/include/oidcc_provider_configuration.hrl").

decode_google_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, Configuration} = file:read_file(PrivDir ++ "/test/fixtures/google-metadata.json"),
    ?assertMatch(
        {ok, #oidcc_provider_configuration{
            issuer = <<"https://accounts.google.com">>,
            token_endpoint =
                <<"https://oauth2.googleapis.com/token">>,
            userinfo_endpoint =
                <<"https://openidconnect.googleapis.com/v1/userinfo">>,
            jwks_uri =
                <<"https://www.googleapis.com/oauth2/v3/certs">>,
            registration_endpoint = undefined,
            scopes_supported =
                [<<"openid">>, <<"email">>, <<"profile">>],
            response_types_supported =
                [
                    <<"code">>,
                    <<"token">>,
                    <<"id_token">>,
                    <<"code token">>,
                    <<"code id_token">>,
                    <<"token id_token">>,
                    <<"code token id_token">>,
                    <<"none">>
                ],
            response_modes_supported =
                [<<"query">>, <<"fragment">>],
            grant_types_supported =
                [
                    <<"authorization_code">>,
                    <<"refresh_token">>,
                    <<"urn:ietf:params:oauth:grant-type:device_code">>,
                    <<"urn:ietf:params:oauth:grant-type:jwt-bearer">>
                ],
            acr_values_supported = undefined,
            subject_types_supported = [public],
            id_token_signing_alg_values_supported =
                [<<"RS256">>],
            id_token_encryption_alg_values_supported =
                undefined,
            id_token_encryption_enc_values_supported =
                undefined,
            userinfo_signing_alg_values_supported = undefined,
            userinfo_encryption_alg_values_supported =
                undefined,
            userinfo_encryption_enc_values_supported =
                undefined,
            request_object_signing_alg_values_supported =
                undefined,
            request_object_encryption_alg_values_supported =
                undefined,
            request_object_encryption_enc_values_supported =
                undefined,
            token_endpoint_auth_methods_supported =
                [
                    <<"client_secret_post">>,
                    <<"client_secret_basic">>
                ],
            token_endpoint_auth_signing_alg_values_supported =
                undefined,
            display_values_supported = undefined,
            claim_types_supported = [normal],
            claims_supported =
                [
                    <<"aud">>,
                    <<"email">>,
                    <<"email_verified">>,
                    <<"exp">>,
                    <<"family_name">>,
                    <<"given_name">>,
                    <<"iat">>,
                    <<"iss">>,
                    <<"locale">>,
                    <<"name">>,
                    <<"picture">>,
                    <<"sub">>
                ],
            service_documentation = undefined,
            claims_locales_supported = undefined,
            ui_locales_supported = undefined,
            claims_parameter_supported = false,
            request_parameter_supported = false,
            request_uri_parameter_supported = true,
            require_request_uri_registration = false,
            op_policy_uri = undefined,
            op_tos_uri = undefined,
            revocation_endpoint =
                <<"https://oauth2.googleapis.com/revoke">>,
            revocation_endpoint_auth_methods_supported =
                [<<"client_secret_basic">>],
            revocation_endpoint_auth_signing_alg_values_supported =
                undefined,
            introspection_endpoint = undefined,
            introspection_endpoint_auth_methods_supported =
                [<<"client_secret_basic">>],
            introspection_endpoint_auth_signing_alg_values_supported =
                undefined,
            code_challenge_methods_supported =
                [<<"plain">>, <<"S256">>],
            extra_fields =
                #{
                    <<"device_authorization_endpoint">> :=
                        <<"https://oauth2.googleapis.com/device/code">>
                }
        }},
        oidcc_provider_configuration:decode_configuration(json:decode(Configuration))
    ).

check_validations_test() ->
    ?assertMatch(
        {error, {invalid_config_property, {uri, issuer}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"issuer">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {uri, authorization_endpoint}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"authorization_endpoint">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {uri, token_endpoint}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"token_endpoint">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {uri_https, userinfo_endpoint}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"userinfo_endpoint">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {uri_https, userinfo_endpoint}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"userinfo_endpoint">> =>
                    <<"file:///foo">>
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {uri, jwks_uri}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"jwks_uri">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {uri, registration_endpoint}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"registration_endpoint">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {list_of_binaries, scopes_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"scopes_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {list_of_binaries, scopes_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"scopes_supported">> =>
                    [
                        <<"test">>,
                        7
                    ]
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {scopes_including_openid, scopes_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"scopes_supported">> =>
                    [<<"without openid">>]
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {list_of_binaries, response_types_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"response_types_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {list_of_binaries, response_modes_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"response_modes_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {list_of_binaries, grant_types_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"grant_types_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {list_of_binaries, acr_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"acr_values_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {list_of_binaries, subject_types_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"subject_types_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {enum, subject_types_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"subject_types_supported">> =>
                    [
                        <<"pairwise">>,
                        <<"public">>,
                        <<"invalid">>
                    ]
            })
        )
    ),

    ?assertMatch(
        {error,
            {invalid_config_property, {list_of_binaries, id_token_signing_alg_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"id_token_signing_alg_values_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error,
            {invalid_config_property, {list_of_binaries, id_token_encryption_alg_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"id_token_encryption_alg_values_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error,
            {invalid_config_property, {list_of_binaries, id_token_encryption_enc_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"id_token_encryption_enc_values_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error,
            {invalid_config_property, {list_of_binaries, userinfo_signing_alg_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"userinfo_signing_alg_values_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error,
            {invalid_config_property, {list_of_binaries, userinfo_encryption_alg_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"userinfo_encryption_alg_values_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error,
            {invalid_config_property, {list_of_binaries, userinfo_encryption_enc_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"userinfo_encryption_enc_values_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error,
            {invalid_config_property,
                {list_of_binaries, request_object_signing_alg_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"request_object_signing_alg_values_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error,
            {invalid_config_property,
                {list_of_binaries, request_object_encryption_alg_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"request_object_encryption_alg_values_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error,
            {invalid_config_property,
                {list_of_binaries, request_object_encryption_enc_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"request_object_encryption_enc_values_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error,
            {invalid_config_property, {list_of_binaries, token_endpoint_auth_methods_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"token_endpoint_auth_methods_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error,
            {invalid_config_property,
                {list_of_binaries, token_endpoint_auth_signing_alg_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"token_endpoint_auth_signing_alg_values_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error,
            {invalid_config_property,
                {alg_no_none, token_endpoint_auth_signing_alg_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"token_endpoint_auth_signing_alg_values_supported">> =>
                    [
                        <<"something">>,
                        <<"none">>
                    ]
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {list_of_binaries, display_values_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"display_values_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {list_of_binaries, claim_types_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"claim_types_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {enum, claim_types_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"claim_types_supported">> =>
                    [
                        <<"normal">>,
                        <<"aggregated">>,
                        <<"distributed">>,
                        <<"invalid">>
                    ]
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {list_of_binaries, claims_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"claims_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {uri, service_documentation}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"service_documentation">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {list_of_binaries, claims_locales_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"claims_locales_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {list_of_binaries, ui_locales_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"ui_locales_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {boolean, claims_parameter_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"claims_parameter_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {boolean, request_parameter_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"request_parameter_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {boolean, request_uri_parameter_supported}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"request_uri_parameter_supported">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {uri, op_policy_uri}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"op_policy_uri">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {invalid_config_property, {uri, op_tos_uri}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"op_tos_uri">> =>
                    7
            })
        )
    ),

    ?assertMatch(
        {error, {missing_config_property, issuer}},
        oidcc_provider_configuration:decode_configuration(#{})
    ),

    ok.

allow_unsafe_http_quirk_test() ->
    ?assertMatch(
        {error, {invalid_config_property, {uri_https, userinfo_endpoint}}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"userinfo_endpoint">> =>
                    <<"http://example.com">>
            })
        )
    ),
    ?assertMatch(
        {ok, _},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{
                <<"userinfo_endpoint">> =>
                    <<"http://example.com">>
            }),
            #{quirks => #{allow_unsafe_http => true}}
        )
    ),

    ok.

document_overrides_quirk_test() ->
    PrivDir = code:priv_dir(oidcc),
    {ok, Configuration} = file:read_file(PrivDir ++ "/test/fixtures/google-metadata.json"),

    ?assertMatch(
        {ok, #oidcc_provider_configuration{
            issuer = <<"https://example.com">>
        }},
        oidcc_provider_configuration:decode_configuration(json:decode(Configuration), #{
            quirks => #{document_overrides => #{<<"issuer">> => <<"https://example.com">>}}
        })
    ),
    ok.

issuer_regex_quirk_test() ->
    PrivDir = code:priv_dir(oidcc),
    {ok, Configuration} = file:read_file(PrivDir ++ "/test/fixtures/google-metadata.json"),
    RegexPattern = <<"^https://[a-z]+\\.google\\.com$">>,

    Result = oidcc_provider_configuration:decode_configuration(json:decode(Configuration), #{
        quirks => #{issuer_regex => RegexPattern}
    }),

    ?assertMatch(
        {ok, #oidcc_provider_configuration{
            issuer = <<"https://accounts.google.com">>,
            issuer_regex = RegexPattern
        }},
        Result
    ),

    ok.

load_configuration_raw_test() ->
    PrivDir = code:priv_dir(oidcc),
    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    Document = json:decode(ConfigurationBinary),

    HttpFun =
        fun(get, _Request, _HttpOpts, _Opts, _Config) ->
            {ok, {
                {"HTTP/1.1", 200, "OK"},
                [{"content-type", "application/json"}],
                ConfigurationBinary
            }}
        end,
    RequestOpts = #{
        request_opts => #{http_adapter => {oidcc_http_adapter_test, #{request => HttpFun}}}
    },

    {ok, {Configuration, Expiry, ReturnedDocument}} =
        oidcc_provider_configuration:load_configuration_raw(<<"https://my.provider">>, RequestOpts),

    ?assertEqual(Document, ReturnedDocument),
    ?assertMatch(#oidcc_provider_configuration{issuer = <<"https://my.provider">>}, Configuration),

    %% The 2-arity function keeps returning the pair, built from the same load.
    ?assertEqual(
        {ok, {Configuration, Expiry}},
        oidcc_provider_configuration:load_configuration(<<"https://my.provider">>, RequestOpts)
    ),

    ok.

load_configuration_raw_returns_wire_document_test() ->
    PrivDir = code:priv_dir(oidcc),
    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),

    HttpFun =
        fun(get, _Request, _HttpOpts, _Opts, _Config) ->
            {ok, {
                {"HTTP/1.1", 200, "OK"},
                [{"content-type", "application/json"}],
                ConfigurationBinary
            }}
        end,

    {ok, {Configuration, _Expiry, Document}} =
        oidcc_provider_configuration:load_configuration_raw(<<"https://my.provider">>, #{
            request_opts => #{http_adapter => {oidcc_http_adapter_test, #{request => HttpFun}}},
            quirks => #{
                document_overrides => #{
                    <<"token_endpoint">> => <<"https://my.provider/override/token">>
                }
            }
        }),

    %% `document_overrides' is merged while decoding, so the record carries the
    %% override while the document stays what the provider served.
    ?assertMatch(
        #oidcc_provider_configuration{token_endpoint = <<"https://my.provider/override/token">>},
        Configuration
    ),
    ?assertEqual(
        maps:get(<<"token_endpoint">>, json:decode(ConfigurationBinary)),
        maps:get(<<"token_endpoint">>, Document)
    ),

    ok.

load_jwks_raw_test() ->
    PrivDir = code:priv_dir(oidcc),
    {ok, JwksBinary} = file:read_file(PrivDir ++ "/test/fixtures/google-jwks.json"),

    HttpFun =
        fun(get, _Request, _HttpOpts, _Opts, _Config) ->
            {ok, {
                {"HTTP/1.1", 200, "OK"},
                [{"content-type", "application/jwk-set+json"}],
                JwksBinary
            }}
        end,
    RequestOpts = #{
        request_opts => #{http_adapter => {oidcc_http_adapter_test, #{request => HttpFun}}}
    },

    {ok, {Jwks, Expiry, Document}} =
        oidcc_provider_configuration:load_jwks_raw(<<"https://my.provider/jwks">>, RequestOpts),

    ?assertEqual(json:decode(JwksBinary), Document),
    ?assertMatch(#{<<"keys">> := _Keys}, Document),
    ?assertEqual(jose_jwk:from(json:decode(JwksBinary)), Jwks),

    ?assertEqual(
        {ok, {Jwks, Expiry}},
        oidcc_provider_configuration:load_jwks(<<"https://my.provider/jwks">>, RequestOpts)
    ),

    ok.

%% The issuer_regex and allow_issuer_mismatch branches return the document from
%% their own clauses, and they are the branches multi-tenant providers take, so
%% they are exactly the population that wants the document persisted.
load_configuration_raw_issuer_mismatch_branches_test() ->
    PrivDir = code:priv_dir(oidcc),
    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),
    Document = json:decode(ConfigurationBinary),

    HttpFun =
        fun(get, _Request, _HttpOpts, _Opts, _Config) ->
            {ok, {
                {"HTTP/1.1", 200, "OK"},
                [{"content-type", "application/json"}],
                ConfigurationBinary
            }}
        end,
    RequestOpts = #{http_adapter => {oidcc_http_adapter_test, #{request => HttpFun}}},

    %% Requested issuer differs from the document's, accepted via issuer_regex.
    ?assertMatch(
        {ok, {#oidcc_provider_configuration{}, _Expiry, Document}},
        oidcc_provider_configuration:load_configuration_raw(<<"https://other.provider">>, #{
            request_opts => RequestOpts,
            quirks => #{issuer_regex => <<"^https://other\\.provider$">>}
        })
    ),

    %% Same, accepted via the deprecated allow_issuer_mismatch quirk.
    ?assertMatch(
        {ok, {#oidcc_provider_configuration{}, _Expiry, Document}},
        oidcc_provider_configuration:load_configuration_raw(<<"https://other.provider">>, #{
            request_opts => RequestOpts,
            quirks => #{allow_issuer_mismatch => true}
        })
    ),

    ?assertMatch(
        {error, {issuer_mismatch, <<"https://my.provider">>}},
        oidcc_provider_configuration:load_configuration_raw(<<"https://other.provider">>, #{
            request_opts => RequestOpts,
            quirks => #{issuer_regex => <<"^https://nope$">>}
        })
    ),

    ok.

%% A syntactically valid JSON document that is not an object used to reach
%% `maps:merge/2' and kill the caller.
load_configuration_raw_non_object_test() ->
    Body = fun(Json) ->
        fun(get, _Request, _HttpOpts, _Opts, _Config) ->
            {ok, {{"HTTP/1.1", 200, "OK"}, [{"content-type", "application/json"}], Json}}
        end
    end,
    Opts = fun(Json) ->
        #{request_opts => #{http_adapter => {oidcc_http_adapter_test, #{request => Body(Json)}}}}
    end,

    ?assertEqual(
        {error, {invalid_document, null}},
        oidcc_provider_configuration:load_configuration(<<"https://my.provider">>, Opts(<<"null">>))
    ),
    ?assertEqual(
        {error, {invalid_document, []}},
        oidcc_provider_configuration:load_configuration(<<"https://my.provider">>, Opts(<<"[]">>))
    ),
    ?assertEqual(
        {error, {invalid_document, 1}},
        oidcc_provider_configuration:load_configuration(<<"https://my.provider">>, Opts(<<"1">>))
    ),

    %% A JWKS may legitimately be a bare array of keys, so only scalars are
    %% rejected there.
    ?assertMatch(
        {ok, {_Jwks, _Expiry, [#{<<"kty">> := <<"oct">>}]}},
        oidcc_provider_configuration:load_jwks_raw(
            <<"https://my.provider/jwks">>,
            Opts(<<"[{\"kty\":\"oct\",\"k\":\"AAAA\"}]">>)
        )
    ),
    ?assertEqual(
        {error, {invalid_document, null}},
        oidcc_provider_configuration:load_jwks_raw(
            <<"https://my.provider/jwks">>, Opts(<<"null">>)
        )
    ),

    ok.

load_configuration_raw_error_test() ->
    HttpFun =
        fun(get, _Request, _HttpOpts, _Opts, _Config) ->
            {ok, {{"HTTP/1.1", 404, "Not Found"}, [], <<>>}}
        end,
    RequestOpts = #{
        request_opts => #{http_adapter => {oidcc_http_adapter_test, #{request => HttpFun}}}
    },

    ?assertMatch(
        {error, {http_error, 404, <<>>}},
        oidcc_provider_configuration:load_configuration_raw(<<"https://my.provider">>, RequestOpts)
    ),
    ?assertMatch(
        {error, {http_error, 404, <<>>}},
        oidcc_provider_configuration:load_jwks_raw(<<"https://my.provider/jwks">>, RequestOpts)
    ),

    ok.

%% A response arriving with almost none of its `max-age` left reports a deadline
%% near zero. Callers drive a refresh timer off it, so the loaders floor it
%% rather than scheduling an immediate reload.
minimum_refresh_floors_stale_response_test() ->
    PrivDir = code:priv_dir(oidcc),
    {ok, ConfigurationBinary} = file:read_file(PrivDir ++ "/test/fixtures/example-metadata.json"),

    Load = fun(CacheHeaders, Opts) ->
        HttpFun =
            fun(get, _Request, _HttpOpts, _Opts, _Config) ->
                {ok, {
                    {"HTTP/1.1", 200, "OK"},
                    [{"content-type", "application/json"} | CacheHeaders],
                    ConfigurationBinary
                }}
            end,
        oidcc_provider_configuration:load_configuration(
            <<"https://my.provider">>,
            maps:merge(Opts, #{
                request_opts => #{
                    http_adapter => {oidcc_http_adapter_test, #{request => HttpFun}}
                }
            })
        )
    end,

    Stale = [{"cache-control", "max-age=3600"}, {"age", "3599"}],

    ?assertMatch(
        {ok, {#oidcc_provider_configuration{}, 60_000}},
        Load(Stale, #{})
    ),
    %% The floor never raises the interval above what the caller asked for as a
    %% fallback, so a caller wanting a shorter one still gets it.
    ?assertMatch(
        {ok, {#oidcc_provider_configuration{}, 5_000}},
        Load(Stale, #{fallback_expiry => 5_000})
    ),

    %% A lifetime comfortably above the floor is passed through, less its Age.
    ?assertMatch(
        {ok, {#oidcc_provider_configuration{}, 240_000}},
        Load([{"cache-control", "max-age=300"}, {"age", "60"}], #{})
    ),

    %% `max-age=0, no-store` still lands on the fallback, as issue #370 needs.
    ?assertMatch(
        {ok, {#oidcc_provider_configuration{}, 12_345}},
        Load([{"cache-control", "max-age=0, no-store"}], #{fallback_expiry => 12_345})
    ),

    ok.

%% The measurement that matters: a nearly-stale provider must not turn the
%% worker into a request loop.
stale_response_does_not_loop_test() ->
    Counter = atomics:new(1, []),
    DiscoveryBody = iolist_to_binary(
        json:encode(#{
            issuer => <<"https://example.com">>,
            jwks_uri => <<"https://example.com/keys">>,
            authorization_endpoint => <<"https://example.com/authorize">>,
            scopes_supported => [<<"openid">>],
            response_types_supported => [<<"code">>],
            subject_types_supported => [<<"public">>],
            id_token_signing_alg_values_supported => [<<"RS256">>]
        })
    ),
    Headers = [
        {"content-type", "application/json"},
        {"cache-control", "max-age=3600"},
        {"age", "3599"}
    ],
    HttpFun =
        fun(get, {Url, []}, _HttpOpts, _Opts, _Profile) ->
            atomics:add(Counter, 1, 1),
            Body =
                case iolist_to_binary(Url) of
                    <<"https://example.com/keys">> ->
                        iolist_to_binary(json:encode(#{keys => []}));
                    _Discovery ->
                        DiscoveryBody
                end,
            {ok, {{"HTTP/1.1", 200, "OK"}, Headers, Body}}
        end,

    {ok, Pid} =
        oidcc_provider_configuration_worker:start_link(#{
            issuer => <<"https://example.com">>,
            provider_configuration_opts => #{
                request_opts => #{
                    http_adapter => {oidcc_http_adapter_test, #{request => HttpFun}}
                }
            }
        }),

    try
        ?assertNotEqual(
            undefined,
            oidcc_provider_configuration_worker:get_provider_configuration(Pid)
        ),
        timer:sleep(1_000),
        %% One discovery plus one JWKS load. Without the floor this was a
        %% sustained one request per second per endpoint.
        ?assert(atomics:get(Counter, 1) =< 4)
    after
        gen_server:stop(Pid)
    end,

    ok.

invalid_json_configuration_test() ->
    HttpFun =
        fun(get, _Request, _HttpOpts, _Opts, _Config) ->
            {ok, {
                {"HTTP/1.1", 200, "OK"},
                [{"content-type", "application/json"}],
                <<"{\"issuer\": ">>
            }}
        end,

    ?assertMatch(
        {error, {invalid_json, _}},
        oidcc_provider_configuration:load_configuration(<<"https://example.com">>, #{
            request_opts => #{
                http_adapter => {oidcc_http_adapter_test, #{request => HttpFun}}
            }
        })
    ),

    ?assertMatch(
        {error, {invalid_json, _}},
        oidcc_provider_configuration:load_jwks(<<"https://example.com/keys">>, #{
            request_opts => #{
                http_adapter => {oidcc_http_adapter_test, #{request => HttpFun}}
            }
        })
    ),

    ok.

uri_concatenation_test() ->
    ok = meck:new(httpc, [no_link]),
    HttpFun =
        fun(get, {ReqEndpoint, _Header}, _HttpOpts, _Opts, _Profile) ->
            self() ! {req, ReqEndpoint},

            {ok, {{"HTTP/1.1", 501, "Not Implemented"}, [], ""}}
        end,
    ok = meck:expect(httpc, request, HttpFun),

    oidcc_provider_configuration:load_configuration("https://example.com"),

    receive
        {req, "https://example.com/.well-known/openid-configuration"} -> ok
    after 0 ->
        ct:fail(timeout_receive_attach_event_handlers)
    end,

    oidcc_provider_configuration:load_configuration("https://example.com/"),

    receive
        {req, "https://example.com/.well-known/openid-configuration"} -> ok
    after 0 ->
        ct:fail(timeout_receive_attach_event_handlers)
    end,

    oidcc_provider_configuration:load_configuration("https://example.com/realm"),

    receive
        {req, "https://example.com/realm/.well-known/openid-configuration"} -> ok
    after 0 ->
        ct:fail(timeout_receive_attach_event_handlers)
    end,

    oidcc_provider_configuration:load_configuration("https://example.com/realm/"),

    receive
        {req, "https://example.com/realm/.well-known/openid-configuration"} -> ok
    after 0 ->
        ct:fail(timeout_receive_attach_event_handlers)
    end,

    meck:unload(httpc),

    ok.

%% OpenID Connect Discovery 1.0 section 2 gives the Issuer Identifier as a URL
%% with no query or fragment. Such an issuer used to build a discovery URL
%% pointing at a different path on the same host.
issuer_query_and_fragment_rejected_test() ->
    Self = self(),
    HttpFun =
        fun(get, {ReqEndpoint, _Header}, _HttpOpts, _Opts, _Config) ->
            Self ! {req, iolist_to_binary(ReqEndpoint)},
            {ok, {{"HTTP/1.1", 501, "Not Implemented"}, [], <<>>}}
        end,
    Opts = #{
        request_opts => #{http_adapter => {oidcc_http_adapter_test, #{request => HttpFun}}}
    },

    lists:foreach(
        fun(Issuer) ->
            ?assertEqual(
                {error, {invalid_issuer, Issuer}},
                oidcc_provider_configuration:load_configuration(Issuer, Opts)
            )
        end,
        [
            <<"https://example.com/realm?tenant=other">>,
            <<"https://example.com/realm#frag">>,
            <<"https://example.com/realm?tenant=other#frag">>,
            <<"https://example.com?tenant=other">>,
            <<"https://example.com/?tenant=other">>,
            <<"https://example.com/realm/?tenant=other">>
        ]
    ),

    %% Rejected before the request is built, so nothing was fetched.
    receive
        {req, Endpoint} -> ?assert({unexpected_request, Endpoint} =:= no_request)
    after 0 -> ok
    end,

    %% An issuer without either component resolves exactly as before.
    lists:foreach(
        fun({Issuer, Expected}) ->
            oidcc_provider_configuration:load_configuration(Issuer, Opts),
            receive
                {req, Got} -> ?assertEqual(Expected, Got)
            after 0 -> ?assert({no_request_for, Issuer} =:= request_made)
            end
        end,
        [
            {<<"https://example.com">>, <<"https://example.com/.well-known/openid-configuration">>},
            {<<"https://example.com/">>,
                <<"https://example.com/.well-known/openid-configuration">>},
            {<<"https://example.com/realm">>,
                <<"https://example.com/realm/.well-known/openid-configuration">>},
            {<<"https://example.com/realm/">>,
                <<"https://example.com/realm/.well-known/openid-configuration">>}
        ]
    ),

    ok.

%% An issuer that fails to parse is not evidence of a query or a fragment.
%% Microsoft Entra ID documents its issuer with a `{tenantid}` placeholder,
%% which `uri_string:parse/1` rejects on the braces.
unparseable_issuer_accepted_test() ->
    Entra = <<"https://login.microsoftonline.com/{tenantid}/v2.0">>,

    ?assertMatch(
        {error, {invalid_issuer, Entra}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{<<"issuer">> => Entra})
        )
    ),

    ?assertMatch(
        {ok, #oidcc_provider_configuration{issuer = Entra}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{<<"issuer">> => Entra}),
            #{quirks => #{issuer_regex => <<"^https://login.microsoftonline.com/[^/]+/v2\\.0$">>}}
        )
    ),

    ok.

%% The issuer a provider states in its own document gets the same check, unless
%% `issuer_regex` says the issuer is not literal.
document_issuer_query_and_fragment_rejected_test() ->
    WithQuery = <<"https://my.provider/realm?tenant=other">>,
    WithFragment = <<"https://my.provider/realm#frag">>,

    ?assertEqual(
        {error, {invalid_issuer, WithQuery}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{<<"issuer">> => WithQuery})
        )
    ),
    ?assertEqual(
        {error, {invalid_issuer, WithFragment}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{<<"issuer">> => WithFragment})
        )
    ),

    %% `issuer_regex` opts the provider out.
    ?assertMatch(
        {ok, #oidcc_provider_configuration{issuer = WithQuery}},
        oidcc_provider_configuration:decode_configuration(
            google_merge_json(#{<<"issuer">> => WithQuery}),
            #{quirks => #{issuer_regex => <<"^https://my.provider">>}}
        )
    ),

    %% An ordinary issuer is untouched.
    ?assertMatch(
        {ok, #oidcc_provider_configuration{issuer = <<"https://accounts.google.com">>}},
        oidcc_provider_configuration:decode_configuration(google_merge_json(#{}))
    ),

    ok.

decode_fapi2_test() ->
    PrivDir = code:priv_dir(oidcc),

    {ok, Configuration} = file:read_file(PrivDir ++ "/test/fixtures/fapi2-metadata.json"),
    ?assertMatch(
        {ok, #oidcc_provider_configuration{
            issuer = <<"https://my.provider">>,
            tls_client_certificate_bound_access_tokens = true,
            mtls_endpoint_aliases = #{
                <<"authorization_endpoint">> := <<"https://my.provider/tls/auth">>,
                <<"registration_endpoint">> := <<"https://my.provider/tls/register">>,
                <<"device_authorization_endpoint">> := <<"https://my.provider/tls/device/code">>,
                <<"token_endpoint">> := <<"https://my.provider/tls/token">>,
                <<"introspection_endpoint">> := <<"https://my.provider/tls/introspection">>,
                <<"userinfo_endpoint">> := <<"https://my.provider/tls/userinfo">>
            }
        }},
        oidcc_provider_configuration:decode_configuration(json:decode(Configuration))
    ),

    ok.

google_merge_json(Merge) ->
    PrivDir = code:priv_dir(oidcc),
    {ok, ValidConfigString} = file:read_file(PrivDir ++ "/test/fixtures/google-metadata.json"),
    Decoded = json:decode(ValidConfigString),
    maps:merge(Decoded, Merge).

use_spec_defaults_in_implicit_configs_test() ->
    PrivDir = code:priv_dir(oidcc),
    {ok, Configuration} = file:read_file(PrivDir ++ "/test/fixtures/example-config-optionals.json"),

    ?assertMatch(
        {ok, #oidcc_provider_configuration{
            issuer = <<"https://my.provider">>,
            token_endpoint_auth_methods_supported = [<<"client_secret_basic">>]
        }},
        oidcc_provider_configuration:decode_configuration(json:decode(Configuration))
    ),

    ok.
