%%%-------------------------------------------------------------------
%% @doc Tooling to load and parse Openid Configuration
%%
%% <h2>Records</h2>
%%
%% To use the record, import the definition:
%%
%% ```
%% -include_lib(["oidcc/include/oidcc_provider_configuration.hrl"]).
%% '''
%%
%% <h2>Telemetry</h2>
%%
%% See {@link 'Elixir.Oidcc.ProviderConfiguration'}
%% @end
%% @since 3.0.0
%%%-------------------------------------------------------------------
-module(oidcc_provider_configuration).

-feature(maybe_expr, enable).

-include("oidcc_provider_configuration.hrl").

-export([decode_configuration/1]).
-export([load_configuration/2]).
-export([load_jwks/2]).

-export_type([error/0]).
-export_type([opts/0]).
-export_type([t/0]).

-type opts() :: #{
    fallback_expiry => timeout(),
    request_opts => oidcc_http_util:request_opts()
}.
%% Configure configuration loading / parsing
%%
%% <h2>Parameters</h2>
%%
%% <ul>
%%   <li>`fallback_expiry' - How long to keep configuration cached if the server doesn't specify expiry</li>
%%   <li>`request_opts' - config for HTTP request</li>
%% </ul>

-type t() ::
    #oidcc_provider_configuration{
        issuer :: uri_string:uri_string(),
        authorization_endpoint :: uri_string:uri_string(),
        token_endpoint :: uri_string:uri_string() | undefined,
        userinfo_endpoint :: uri_string:uri_string() | undefined,
        jwks_uri :: uri_string:uri_string() | undefined,
        registration_endpoint :: uri_string:uri_string() | undefined,
        scopes_supported :: [binary()] | undefined,
        response_types_supported :: [binary()],
        response_modes_supported :: [binary()],
        grant_types_supported :: [binary()],
        acr_values_supported :: [binary()] | undefined,
        subject_types_supported :: [pairwise | public],
        id_token_signing_alg_values_supported :: [binary()],
        id_token_encryption_alg_values_supported ::
            [binary()] | undefined,
        id_token_encryption_enc_values_supported ::
            [binary()] | undefined,
        userinfo_signing_alg_values_supported :: [binary()] | undefined,
        userinfo_encryption_alg_values_supported ::
            [binary()] | undefined,
        userinfo_encryption_enc_values_supported ::
            [binary()] | undefined,
        request_object_signing_alg_values_supported ::
            [binary()] | undefined,
        request_object_encryption_alg_values_supported ::
            [binary()] | undefined,
        request_object_encryption_enc_values_supported ::
            [binary()] | undefined,
        token_endpoint_auth_methods_supported :: [binary()],
        token_endpoint_auth_signing_alg_values_supported ::
            [binary()] | undefined,
        display_values_supported :: [binary()] | undefined,
        claim_types_supported :: [normal | aggregated | distributed],
        claims_supported :: [binary()] | undefined,
        service_documentation :: uri_string:uri_string() | undefined,
        claims_locales_supported :: [binary()] | undefined,
        ui_locales_supported :: [binary()] | undefined,
        claims_parameter_supported :: boolean(),
        request_parameter_supported :: boolean(),
        request_uri_parameter_supported :: boolean(),
        require_request_uri_registration :: boolean(),
        op_policy_uri :: uri_string:uri_string() | undefined,
        op_tos_uri :: uri_string:uri_string() | undefined,
        revocation_endpoint :: uri_string:uri_string() | undefined,
        revocation_endpoint_auth_methods_supported :: [binary()],
        revocation_endpoint_auth_signing_alg_values_supported ::
            [binary()] | undefined,
        introspection_endpoint :: uri_string:uri_string() | undefined,
        introspection_endpoint_auth_methods_supported :: [binary()],
        introspection_endpoint_auth_signing_alg_values_supported ::
            [binary()] | undefined,
        code_challenge_methods_supported :: [binary()] | undefined,
        extra_fields :: #{binary() => term()}
    }.
%% Record containing OpenID and OAuth 2.0 Configuration
%%
%% See [https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata] and
%% [https://datatracker.ietf.org/doc/html/draft-jones-oauth-discovery-01#section-4.1]
%%
%% All unrecognized fields are stored in `extra_fields'.

-type error() ::
    invalid_content_type
    | {missing_config_property, Key :: atom()}
    | {invalid_config_property, {
        Type ::
            uri
            | uri_https
            | list_of_binaries
            | boolean
            | scopes_including_openid
            | enum
            | alg_no_none,
        Field :: atom()
    }}
    | oidcc_http_util:error().

-define(DEFAULT_CONFIG_EXPIRY, timer:minutes(15)).

-telemetry_event(#{
    event => [oidcc, load_configuration, start],
    description => <<"Emitted at the start of loading the provider configuration">>,
    measurements => <<"#{system_time => non_neg_integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string()}">>
}).

-telemetry_event(#{
    event => [oidcc, load_configuration, stop],
    description => <<"Emitted at the end of loading the provider configuration">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string()}">>
}).

-telemetry_event(#{
    event => [oidcc, load_configuration, exception],
    description => <<"Emitted at the end of loading the provider configuration">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{issuer => uri_string:uri_string()}">>
}).

-telemetry_event(#{
    event => [oidcc, load_jwks, start],
    description => <<"Emitted at the start of loading the provider jwks">>,
    measurements => <<"#{system_time => non_neg_integer()}">>,
    metadata => <<"#{jwks_uri => uri_string:uri_string()}">>
}).

-telemetry_event(#{
    event => [oidcc, load_jwks, stop],
    description => <<"Emitted at the end of loading the provider jwks">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{jwks_uri => uri_string:uri_string()}">>
}).

-telemetry_event(#{
    event => [oidcc, load_jwks, exception],
    description => <<"Emitted at the end of loading the provider jwks">>,
    measurements => <<"#{duration => integer(), monotonic_time => integer()}">>,
    metadata => <<"#{jwks_uri => uri_string:uri_string()}">>
}).

%% @doc Load OpenID Configuration into a {@link oidcc_provider_configuration:t()} record
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, #oidcc_provider_configuration{}} =
%%   oidcc_provider_configuration:load_configuration("https://accounts.google.com").
%% '''
%% @end
%% @since 3.0.0
-spec load_configuration(Issuer, Opts) ->
    {ok, {Configuration :: t(), Expiry :: pos_integer()}} | {error, error()}
when
    Issuer :: uri_string:uri_string(),
    Opts :: opts().
load_configuration(Issuer, Opts) ->
    TelemetryOpts = #{topic => [oidcc, load_configuration], extra_meta => #{issuer => Issuer}},
    RequestOpts = maps:get(request_opts, Opts, #{}),
    Request = {[Issuer, <<"/.well-known/openid-configuration">>], []},

    maybe
        {ok, {{json, ConfigurationMap}, Headers}} ?= oidcc_http_util:request(get, Request, TelemetryOpts, RequestOpts),
        Expiry = headers_to_deadline(Headers, Opts),
        {ok, Configuration} ?= decode_configuration(ConfigurationMap),
        {ok, {Configuration, Expiry}}
    else
        {error, Reason} -> {error, Reason};
        {ok, {{_Format, _Body}, _Headers}} -> {error, invalid_content_type}
    end.

%% @doc Load JWKs into a {@link jose_jwk:key()} record
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, #jose_jwk{}} =
%%   oidcc_provider_configuration:load_jwks("https://www.googleapis.com/oauth2/v3/certs").
%% '''
%% @end
%% @since 3.0.0
-spec load_jwks(JwksUri, Opts) ->
    {ok, {Jwks :: jose_jwk:key(), Expiry :: pos_integer()}} | {error, term()}
when
    JwksUri :: uri_string:uri_string(),
    Opts :: opts().
load_jwks(JwksUri, Opts) ->
    TelemetryOpts = #{topic => [oidcc, load_jwks], extra_meta => #{jwks_uri => JwksUri}},
    RequestOpts = maps:get(request_opts, Opts, #{}),

    maybe
        {ok, {{json, JwksBinary}, Headers}} ?= oidcc_http_util:request(get, {JwksUri, []}, TelemetryOpts, RequestOpts),
        Expiry = headers_to_deadline(Headers, Opts),
        Jwks = jose_jwk:from(JwksBinary),
        {ok, {Jwks, Expiry}}
    else
        {error, Reason} -> {error, Reason};
        {ok, {{_Format, _Body}, _Headers}} -> {error, invalid_content_type}
    end.

%% @doc Decode JSON into a {@link oidcc_provider_configuration:t()} record
%%
%% <h2>Examples</h2>
%%
%% ```
%% {ok, {{"HTTP/1.1",200,"OK"}, _Headers, Body}} =
%%   httpc:request("https://accounts.google.com/.well-known/openid-configuration"),
%%
%% {ok, DecodedJson} = your_json_lib:decode(Body),
%%
%% {ok, #oidcc_provider_configuration{}} =
%%   oidcc_provider_configuration:decode_configuration(DecodedJson).
%% '''
%% @end
%% @since 3.0.0
-spec decode_configuration(Configuration :: map()) -> {ok, t()} | {error, error()}.
decode_configuration(Configuration) ->
    maybe
        {ok,
         {#{issuer := Issuer,
            authorization_endpoint := AuthorizationEndpoint,
            authorization_endpoint := AuthorizationEndpoint,
            token_endpoint := TokenEndpoint,
            userinfo_endpoint := UserinfoEndpoint,
            jwks_uri := JwksUri,
            registration_endpoint := RegistrationEndpoint,
            scopes_supported := ScopesSupported,
            response_types_supported := ResponseTypesSupported,
            response_modes_supported := ResponseModesSupported,
            grant_types_supported := GrantTypesSupported,
            acr_values_supported := AcrValuesSupported,
            subject_types_supported := SubjectTypesSupported,
            id_token_signing_alg_values_supported := IdTokenSigningAlgValuesSupported,
            id_token_encryption_alg_values_supported := IdTokenEncryptionAlgValuesSupported,
            id_token_encryption_enc_values_supported := IdTokenEncryptionEncValuesSupported,
            userinfo_signing_alg_values_supported := UserinfoSigningAlgValuesSupported,
            userinfo_encryption_alg_values_supported := UserinfoEncryptionAlgValuesSupported,
            userinfo_encryption_enc_values_supported := UserinfoEncryptionEncValuesSupported,
            request_object_signing_alg_values_supported := RequestObjectSigningAlgValuesSupported,
            request_object_encryption_alg_values_supported :=
                RequestObjectEncryptionAlgValuesSupported,
            request_object_encryption_enc_values_supported :=
                RequestObjectEncryptionEncValuesSupported,
            token_endpoint_auth_methods_supported := TokenEndpointAuthMethodsSupported,
            token_endpoint_auth_signing_alg_values_supported :=
                TokenEndpointAuthSigningAlgValuesSupported,
            display_values_supported := DisplayValuesSupported,
            claim_types_supported := ClaimTypesSupported,
            claims_supported := ClaimsSupported,
            service_documentation := ServiceDocumentation,
            claims_locales_supported := ClaimsLocalesSupported,
            ui_locales_supported := UiLocalesSupported,
            claims_parameter_supported := ClaimsParameterSupported,
            request_parameter_supported := RequestParameterSupported,
            request_uri_parameter_supported := RequestUriParameterSupported,
            require_request_uri_registration := RequireRequestUriRegistration,
            op_policy_uri := OpPolicyUri,
            op_tos_uri := OpTosUri,
            revocation_endpoint := RevocationEndpoint,
            revocation_endpoint_auth_methods_supported := RevocationEndpointAuthMethodsSupported,
            revocation_endpoint_auth_signing_alg_values_supported :=
                RevocationEndpointAuthSigningAlgValuesSupported,
            introspection_endpoint := IntrospectionEndpoint,
            introspection_endpoint_auth_methods_supported :=
                IntrospectionEndpointAuthMethodsSupported,
            introspection_endpoint_auth_signing_alg_values_supported :=
                IntrospectionEndpointAuthSigningAlgValuesSupported,
            code_challenge_methods_supported := CodeChallengeMethodsSupported},
          ExtraFields}} ?=
            configuration_extract(Configuration,
                             [{required, issuer, fun parse_setting_uri/2},
                              {required, authorization_endpoint, fun parse_setting_uri/2},
                              {optional, token_endpoint, undefined, fun parse_setting_uri/2},
                              {optional,
                               userinfo_endpoint,
                               undefined,
                               fun parse_setting_uri_https/2},
                              {required, jwks_uri, fun parse_setting_uri/2},
                              {optional, registration_endpoint, undefined, fun parse_setting_uri/2},
                              {required, scopes_supported, fun parse_scopes_supported/2},
                              {required, response_types_supported, fun parse_setting_binary_list/2},
                              {optional,
                               response_modes_supported,
                               [<<"query">>, <<"fragment">>],
                               fun parse_setting_binary_list/2},
                              {optional,
                               grant_types_supported,
                               [<<"authorization_code">>, <<"implicit">>],
                               fun parse_setting_binary_list/2},
                              {optional,
                               acr_values_supported,
                               undefined,
                               fun parse_setting_binary_list/2},
                              {required,
                               subject_types_supported,
                               fun parse_subject_types_supported/2},
                              {required,
                               id_token_signing_alg_values_supported,
                               fun parse_setting_binary_list/2},
                              {optional,
                               id_token_encryption_alg_values_supported,
                               undefined,
                               fun parse_setting_binary_list/2},
                              {optional,
                               id_token_encryption_enc_values_supported,
                               undefined,
                               fun parse_setting_binary_list/2},
                              {optional,
                               userinfo_signing_alg_values_supported,
                               undefined,
                               fun parse_setting_binary_list/2},
                              {optional,
                               userinfo_encryption_alg_values_supported,
                               undefined,
                               fun parse_setting_binary_list/2},
                              {optional,
                               userinfo_encryption_enc_values_supported,
                               undefined,
                               fun parse_setting_binary_list/2},
                              {optional,
                               request_object_signing_alg_values_supported,
                               undefined,
                               fun parse_setting_binary_list/2},
                              {optional,
                               request_object_encryption_alg_values_supported,
                               undefined,
                               fun parse_setting_binary_list/2},
                              {optional,
                               request_object_encryption_enc_values_supported,
                               undefined,
                               fun parse_setting_binary_list/2},
                              {optional,
                               token_endpoint_auth_methods_supported,
                               undefined,
                               fun parse_setting_binary_list/2},
                              {optional,
                               token_endpoint_auth_signing_alg_values_supported,
                               undefined,
                               fun parse_token_signing_alg_values_no_none/2},
                              {optional,
                               display_values_supported,
                               undefined,
                               fun parse_setting_binary_list/2},
                              {optional,
                               claim_types_supported,
                               [normal],
                               fun parse_claim_types_supported/2},
                              {optional,
                               claims_supported,
                               undefined,
                               fun parse_setting_binary_list/2},
                              {optional, service_documentation, undefined, fun parse_setting_uri/2},
                              {optional,
                               claims_locales_supported,
                               undefined,
                               fun parse_setting_binary_list/2},
                              {optional,
                               ui_locales_supported,
                               undefined,
                               fun parse_setting_binary_list/2},
                              {optional,
                               claims_parameter_supported,
                               false,
                               fun parse_setting_boolean/2},
                              {optional,
                               request_parameter_supported,
                               false,
                               fun parse_setting_boolean/2},
                              {optional,
                               request_uri_parameter_supported,
                               true,
                               fun parse_setting_boolean/2},
                              {optional,
                               require_request_uri_registration,
                               false,
                               fun parse_setting_boolean/2},
                              {optional, op_policy_uri, undefined, fun parse_setting_uri/2},
                              {optional, op_tos_uri, undefined, fun parse_setting_uri/2},
                              {optional, revocation_endpoint, undefined, fun parse_setting_uri/2},
                              {optional,
                               revocation_endpoint_auth_methods_supported,
                               [<<"client_secret_basic">>],
                               fun parse_setting_binary_list/2},
                              {optional,
                               revocation_endpoint_auth_signing_alg_values_supported,
                               undefined,
                               fun parse_token_signing_alg_values_no_none/2},
                              {optional,
                               introspection_endpoint,
                               undefined,
                               fun parse_setting_uri/2},
                              {optional,
                               introspection_endpoint_auth_methods_supported,
                               [<<"client_secret_basic">>],
                               fun parse_setting_binary_list/2},
                              {optional,
                               introspection_endpoint_auth_signing_alg_values_supported,
                               undefined,
                               fun parse_token_signing_alg_values_no_none/2},
                              {optional,
                               code_challenge_methods_supported,
                               undefined,
                               fun parse_setting_binary_list/2}],
                             #{}),
        {ok,
         #oidcc_provider_configuration{issuer = Issuer,
                                       authorization_endpoint = AuthorizationEndpoint,
                                       token_endpoint = TokenEndpoint,
                                       userinfo_endpoint = UserinfoEndpoint,
                                       jwks_uri = JwksUri,
                                       registration_endpoint = RegistrationEndpoint,
                                       scopes_supported = ScopesSupported,
                                       response_types_supported = ResponseTypesSupported,
                                       response_modes_supported = ResponseModesSupported,
                                       grant_types_supported = GrantTypesSupported,
                                       acr_values_supported = AcrValuesSupported,
                                       subject_types_supported = SubjectTypesSupported,
                                       id_token_signing_alg_values_supported =
                                           IdTokenSigningAlgValuesSupported,
                                       id_token_encryption_alg_values_supported =
                                           IdTokenEncryptionAlgValuesSupported,
                                       id_token_encryption_enc_values_supported =
                                           IdTokenEncryptionEncValuesSupported,
                                       userinfo_signing_alg_values_supported =
                                           UserinfoSigningAlgValuesSupported,
                                       userinfo_encryption_alg_values_supported =
                                           UserinfoEncryptionAlgValuesSupported,
                                       userinfo_encryption_enc_values_supported =
                                           UserinfoEncryptionEncValuesSupported,
                                       request_object_signing_alg_values_supported =
                                           RequestObjectSigningAlgValuesSupported,
                                       request_object_encryption_alg_values_supported =
                                           RequestObjectEncryptionAlgValuesSupported,
                                       request_object_encryption_enc_values_supported =
                                           RequestObjectEncryptionEncValuesSupported,
                                       token_endpoint_auth_methods_supported =
                                           TokenEndpointAuthMethodsSupported,
                                       token_endpoint_auth_signing_alg_values_supported =
                                           TokenEndpointAuthSigningAlgValuesSupported,
                                       display_values_supported = DisplayValuesSupported,
                                       claim_types_supported = ClaimTypesSupported,
                                       claims_supported = ClaimsSupported,
                                       service_documentation = ServiceDocumentation,
                                       claims_locales_supported = ClaimsLocalesSupported,
                                       ui_locales_supported = UiLocalesSupported,
                                       claims_parameter_supported = ClaimsParameterSupported,
                                       request_parameter_supported = RequestParameterSupported,
                                       request_uri_parameter_supported =
                                           RequestUriParameterSupported,
                                       require_request_uri_registration =
                                           RequireRequestUriRegistration,
                                       op_policy_uri = OpPolicyUri,
                                       op_tos_uri = OpTosUri,
                                       revocation_endpoint = RevocationEndpoint,
                                       revocation_endpoint_auth_methods_supported =
                                           RevocationEndpointAuthMethodsSupported,
                                       revocation_endpoint_auth_signing_alg_values_supported =
                                           RevocationEndpointAuthSigningAlgValuesSupported,
                                       introspection_endpoint = IntrospectionEndpoint,
                                       introspection_endpoint_auth_methods_supported =
                                           IntrospectionEndpointAuthMethodsSupported,
                                       introspection_endpoint_auth_signing_alg_values_supported =
                                           IntrospectionEndpointAuthSigningAlgValuesSupported,
                                       code_challenge_methods_supported =
                                           CodeChallengeMethodsSupported,
                                       extra_fields = ExtraFields}}
    end.

-spec configuration_extract(
    Map :: #{binary() => term()},
    Keys :: [{required, Key, ParseFn} | {optional, Key, Default, ParseFn}],
    Acc :: #{atom() => term()}
) ->
    {ok, {Matched, Rest}} | {error, error()}
when
    Key :: atom(),
    Default :: term(),
    ParseFn :: fun((Setting :: term(), Key) -> {ok, term()} | {error, error()}),
    Matched :: #{Key => Default | undefined | term()},
    Rest :: #{binary() => term()}.
configuration_extract(Map1, [{required, Key, ParseFn} | RestKeys], Acc) ->
    case maps:take(atom_to_binary(Key), Map1) of
        {Value, Map2} ->
            case ParseFn(Value, Key) of
                {ok, Parsed} ->
                    configuration_extract(Map2, RestKeys, maps:put(Key, Parsed, Acc));
                {error, Reason} ->
                    {error, Reason}
            end;
        error ->
            {error, {missing_config_property, Key}}
    end;
configuration_extract(Map1, [{optional, Key, Default, ParseFn} | RestKeys], Acc) ->
    case maps:take(atom_to_binary(Key), Map1) of
        {Value, Map2} ->
            case ParseFn(Value, Key) of
                {ok, Parsed} ->
                    configuration_extract(Map2, RestKeys, maps:put(Key, Parsed, Acc));
                {error, Reason} ->
                    {error, Reason}
            end;
        error ->
            configuration_extract(Map1, RestKeys, maps:put(Key, Default, Acc))
    end;
configuration_extract(Map, [], Acc) ->
    {ok, {Acc, Map}}.

-spec headers_to_deadline(Headers, Opts) -> pos_integer() when
    Headers :: [{Header :: binary(), Value :: binary()}], Opts :: opts().
headers_to_deadline(Headers, Opts) ->
    DefaultExpiry = maps:get(fallback_expiry, Opts, ?DEFAULT_CONFIG_EXPIRY),
    case proplists:lookup("cache-control", Headers) of
        {"cache-control", Cache} ->
            try
                cache_deadline(Cache, DefaultExpiry)
            catch
                _:_ ->
                    DefaultExpiry
            end;
        none ->
            DefaultExpiry
    end.

-spec cache_deadline(Cache :: iodata(), Fallback :: pos_integer()) -> pos_integer().
cache_deadline(Cache, Fallback) ->
    Entries =
        binary:split(iolist_to_binary(Cache), [<<",">>, <<"=">>, <<" ">>], [global, trim_all]),
    MaxAge =
        fun
            (<<"0">>, Res) ->
                Res;
            (Entry, true) ->
                erlang:convert_time_unit(binary_to_integer(Entry), second, millisecond);
            (<<"max-age">>, _) ->
                true;
            (_, Res) ->
                Res
        end,
    lists:foldl(MaxAge, Fallback, Entries).

-spec parse_setting_uri(Setting :: term(), Field :: atom()) ->
    {ok, uri_string:uri_string()} | {error, error()}.
parse_setting_uri(Setting, _Field) when is_binary(Setting) ->
    {ok, Setting};
parse_setting_uri(_Setting, Field) ->
    {error, {invalid_config_property, {uri, Field}}}.

-spec parse_setting_uri_https(Setting :: term(), Field :: atom()) ->
    {ok, uri_string:uri_string()} | {error, error()}.
parse_setting_uri_https(Setting, Field) when is_binary(Setting) ->
    case uri_string:parse(Setting) of
        #{scheme := <<"https">>} ->
            {ok, Setting};
        #{scheme := _Scheme} ->
            {error, {invalid_config_property, {uri_https, Field}}}
    end;
parse_setting_uri_https(_Setting, Field) ->
    {error, {invalid_config_property, {uri_https, Field}}}.

-spec parse_setting_binary_list(Setting :: term(), Field :: atom()) ->
    {ok, [binary()]} | {error, error()}.
parse_setting_binary_list(Setting, Field) when is_list(Setting) ->
    case lists:all(fun is_binary/1, Setting) of
        true ->
            {ok, Setting};
        false ->
            {error, {invalid_config_property, {list_of_binaries, Field}}}
    end;
parse_setting_binary_list(_Setting, Field) ->
    {error, {invalid_config_property, {list_of_binaries, Field}}}.

-spec parse_setting_boolean(Setting :: term(), Field :: atom()) ->
    {ok, boolean()} | {error, error()}.
parse_setting_boolean(Setting, _Field) when is_boolean(Setting) ->
    {ok, Setting};
parse_setting_boolean(_Setting, Field) ->
    {error, {invalid_config_property, {boolean, Field}}}.

-spec parse_scopes_supported(Setting :: term(), Field :: atom()) ->
    {ok, [binary()]} | {error, error()}.
parse_scopes_supported(Setting, Field) ->
    case parse_setting_binary_list(Setting, Field) of
        {ok, Scopes} ->
            case lists:member(<<"openid">>, Scopes) of
                true ->
                    {ok, Scopes};
                false ->
                    {error, {invalid_config_property, {scopes_including_openid, Field}}}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

-spec parse_setting_list_enum(
    Setting :: term(),
    Field :: atom(),
    Parse :: fun((binary()) -> {ok, Value} | error)
) ->
    {ok, [Value]} | {error, error()}
when
    Value :: term().
parse_setting_list_enum(Setting, Field, Parse) ->
    case parse_setting_binary_list(Setting, Field) of
        {ok, Values} ->
            Parsed =
                lists:map(
                    fun(Value) ->
                        case Parse(Value) of
                            {ok, ParsedValue} ->
                                {ok, ParsedValue};
                            error ->
                                {error, Value}
                        end
                    end,
                    Values
                ),

            case
                lists:filter(
                    fun
                        ({ok, _Value}) ->
                            false;
                        ({error, _Value}) ->
                            true
                    end,
                    Parsed
                )
            of
                [] ->
                    {ok, lists:map(fun({ok, Value}) -> Value end, Parsed)};
                [{error, _InvalidValue} | _Rest] ->
                    {error, {invalid_config_property, {enum, Field}}}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

-spec parse_subject_types_supported(Setting :: term(), Field :: atom()) ->
    {ok, [binary()]} | {error, error()}.
parse_subject_types_supported(Setting, Field) ->
    parse_setting_list_enum(
        Setting,
        Field,
        fun
            (<<"pairwise">>) ->
                {ok, pairwise};
            (<<"public">>) ->
                {ok, public};
            (_SubjectType) ->
                error
        end
    ).

-spec parse_token_signing_alg_values_no_none(Setting :: term(), Field :: atom()) ->
    {ok, [binary()]} | {error, error()}.
parse_token_signing_alg_values_no_none(Setting, Field) ->
    case parse_setting_binary_list(Setting, Field) of
        {ok, SigningAlgValues} ->
            case
                lists:any(
                    fun
                        (<<"none">>) ->
                            true;
                        (_) ->
                            false
                    end,
                    SigningAlgValues
                )
            of
                false ->
                    {ok, SigningAlgValues};
                true ->
                    {error, {invalid_config_property, {alg_no_none, Field}}}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

-spec parse_claim_types_supported(Setting :: term(), Field :: atom()) ->
    {ok, [binary()]} | {error, error()}.
parse_claim_types_supported(Setting, Field) ->
    parse_setting_list_enum(
        Setting,
        Field,
        fun
            (<<"normal">>) ->
                {ok, normal};
            (<<"aggregated">>) ->
                {ok, aggregated};
            (<<"distributed">>) ->
                {ok, distributed};
            (_ClaimType) ->
                error
        end
    ).
