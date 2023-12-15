%%%-------------------------------------------------------------------
%% @doc JWT Utilities
%% @end
%%%-------------------------------------------------------------------
-module(oidcc_jwt_util).

-feature(maybe_expr, enable).

-include_lib("jose/include/jose_jwk.hrl").
-include_lib("jose/include/jose_jws.hrl").
-include_lib("jose/include/jose_jwt.hrl").

-export([client_secret_oct_keys/2]).
-export([encrypt/4]).
-export([evaluate_for_all_keys/2]).
-export([merge_jwks/2]).
-export([refresh_jwks_fun/1]).
-export([sign/3]).
-export([sign/4]).
-export([verify_claims/2]).
-export([verify_signature/3]).

-export_type([claims/0]).
-export_type([error/0]).
-export_type([refresh_jwks_for_unknown_kid_fun/0]).

-type refresh_jwks_for_unknown_kid_fun() ::
    fun((Jwks :: jose_jwk:key(), Kid :: binary()) -> {ok, jose_jwk:key()} | {error, term()}).

-type error() ::
    no_matching_key
    | invalid_jwt_token
    | {no_matching_key_with_kid, Kid :: binary()}
    | {none_alg_used, Jwt :: #jose_jwt{}, Jws :: #jose_jws{}}.

-type claims() :: #{binary() => term()}.

%% Function to decide if the jwks should be reladed to find a matching key for `Kid'
%%
%% A default function is provided in {@link oidcc:retrieve_token/5}
%% and {@link oidcc:retrieve_userinfo/5}.
%%
%% The default implementation does not implement any rate limiting.

%% @private
%% Checking of jwk sets is a bit wonky because of partial support
%% in jose. see: https://github.com/potatosalad/erlang-jose/issues/28
-spec verify_signature(Token, AllowAlgorithms, Jwks) ->
    {ok, {Jwt, Jws}}
    | {error, error()}
when
    Token :: binary(),
    AllowAlgorithms :: [binary()],
    Jwks :: jose_jwk:key(),
    Jwt :: #jose_jwt{},
    Jws :: #jose_jws{}.
verify_signature(Token, AllowAlgorithms, #jose_jwk{keys = {jose_jwk_set, Keys}}) ->
    lists:foldl(
        fun
            (_Key, {ok, _Res} = Acc) ->
                Acc;
            (Key, Acc) ->
                case {verify_signature(Token, AllowAlgorithms, Key), Acc} of
                    {{ok, Res}, _Acc} ->
                        {ok, Res};
                    {_Res, {error, {no_matching_key_with_kid, Kid}}} ->
                        {error, {no_matching_key_with_kid, Kid}};
                    {Res, _Acc} ->
                        Res
                end
        end,
        {error, no_matching_key},
        Keys
    );
verify_signature(Token, AllowAlgorithms, #jose_jwk{} = Jwks) ->
    try
        Kid =
            case jose_jwt:peek_protected(Token) of
                #jose_jws{fields = #{<<"kid">> := IntKid}} ->
                    IntKid;
                #jose_jws{} ->
                    none
            end,
        case Jwks of
            #jose_jwk{fields = #{<<"kid">> := CmpKid}} when CmpKid =/= Kid, Kid =/= none ->
                {error, {no_matching_key_with_kid, Kid}};
            #jose_jwk{} ->
                case jose_jwt:verify_strict(Jwks, AllowAlgorithms, Token) of
                    {true, Jwt, Jws} ->
                        {ok, {Jwt, Jws}};
                    {false, Jwt, #jose_jws{alg = {jose_jws_alg_none, none}} = Jws} ->
                        {error, {none_alg_used, Jwt, Jws}};
                    {false, _Jwt, _Jws} ->
                        {error, no_matching_key}
                end
        end
    catch
        error:{badarg, [_Token]} ->
            {error, invalid_jwt_token};
        %% Some Keys crash if a non matching alg is provided
        error:function_clause ->
            {error, invalid_jwt_token}
    end.

%% @private
-spec verify_claims(Claims, ExpClaims) -> ok | {error, {missing_claim, ExpClaim, Claims}} when
    Claims :: claims(),
    ExpClaim :: {binary(), term()},
    ExpClaims :: [ExpClaim].
verify_claims(Claims, ExpClaims) ->
    CheckExpectedClaims =
        fun({Key, Value}) ->
            case maps:get(Key, Claims, none) of
                Value ->
                    false;
                _Other ->
                    true
            end
        end,
    case lists:filter(CheckExpectedClaims, ExpClaims) of
        [] ->
            ok;
        [Claim | _Rest] ->
            {error, {missing_claim, Claim, Claims}}
    end.

%% @private
-spec client_secret_oct_keys(AllowedAlgorithms, ClientSecret) -> jose_jwk:key() | none when
    AllowedAlgorithms :: [binary()] | undefined,
    ClientSecret :: binary().
client_secret_oct_keys(undefined, _ClientSecret) ->
    none;
client_secret_oct_keys(AllowedAlgorithms, ClientSecret) ->
    case
        lists:member(<<"HS256">>, AllowedAlgorithms) or
            lists:member(<<"HS384">>, AllowedAlgorithms) or
            lists:member(<<"HS512">>, AllowedAlgorithms)
    of
        true ->
            Jwk = jose_jwk:from_oct(ClientSecret),
            Jwk#jose_jwk{fields = maps:merge(Jwk#jose_jwk.fields, #{<<"use">> => <<"sig">>})};
        false ->
            none
    end.

%% @private
-spec refresh_jwks_fun(ProviderConfigurationWorkerName) ->
    refresh_jwks_for_unknown_kid_fun()
when
    ProviderConfigurationWorkerName :: gen_server:server_ref().
refresh_jwks_fun(ProviderConfigurationWorkerName) ->
    fun(_Jwks, Kid) ->
        oidcc_provider_configuration_worker:refresh_jwks_for_unknown_kid(
            ProviderConfigurationWorkerName,
            Kid
        ),
        {ok, oidcc_provider_configuration_worker:get_jwks(ProviderConfigurationWorkerName)}
    end.

%% @private
-spec merge_jwks(Left :: jose_jwk:key(), Right :: jose_jwk:key()) -> jose_jwk:key().
merge_jwks(#jose_jwk{keys = {jose_jwk_set, LeftKeys}, fields = LeftFields}, #jose_jwk{
    keys = {jose_jwk_set, RightKeys}, fields = RightFields
}) ->
    #jose_jwk{
        keys = {jose_jwk_set, LeftKeys ++ RightKeys}, fields = maps:merge(LeftFields, RightFields)
    };
merge_jwks(#jose_jwk{} = Left, #jose_jwk{keys = {jose_jwk_set, _RightKeys}} = Right) ->
    merge_jwks(#jose_jwk{keys = {jose_jwk_set, [Left]}}, Right);
merge_jwks(Left, Right) ->
    merge_jwks(Left, #jose_jwk{keys = {jose_jwk_set, [Right]}}).

%% @private
-spec sign(Jwt :: #jose_jwt{}, Jwk :: jose_jwk:key(), SupportedAlgorithms :: [binary()]) ->
    {ok, binary()} | {error, no_supported_alg_or_key}.
sign(Jwt, Jwk, SupportedAlgorithms) ->
    sign(Jwt, Jwk, SupportedAlgorithms, #{}).

%% @private
-spec sign(
    Jwt :: #jose_jwt{}, Jwk :: jose_jwk:key(), SupportedAlgorithms :: [binary()], JwsFields :: map()
) ->
    {ok, binary()} | {error, no_supported_alg_or_key}.
sign(_Jwt, _Jwk, [], _JwsFields) ->
    {error, no_supported_alg_or_key};
sign(Jwt, Jwk, [Algorithm | RestAlgorithms], JwsFields0) ->
    maybe
        #jose_jws{fields = JwsFields} =
            Jws0 ?= jose_jws:from_map(JwsFields0#{<<"alg">> => Algorithm}),
        SigningCallback = fun
            (#jose_jwk{fields = #{<<"use">> := <<"sig">>} = Fields} = Key) ->
                %% add the kid field to the JWS signature if present
                KidField = maps:with([<<"kid">>], Fields),
                Jws = Jws0#jose_jws{fields = maps:merge(KidField, JwsFields)},
                try
                    {_Jws, Token} = jose_jws:compact(jose_jwt:sign(Key, Jws, Jwt)),
                    {ok, Token}
                catch
                    error:not_supported -> error;
                    error:{not_supported, _Alg} -> error;
                    %% Some Keys crash if a public key is provided
                    error:function_clause -> error
                end;
            (#jose_jwk{} = Key) when Algorithm == <<"none">> ->
                try
                    {_Jws, Token} = jose_jws:compact(jose_jwt:sign(Key, Jws0, Jwt)),
                    {ok, Token}
                catch
                    error:not_supported -> error;
                    error:{not_supported, _Alg} -> error
                end;
            (_Key) ->
                error
        end,
        {ok, Token} ?= evaluate_for_all_keys(Jwk, SigningCallback),
        {ok, Token}
    else
        _ -> sign(Jwt, Jwk, RestAlgorithms, JwsFields0)
    end.

%% @private
-spec encrypt(
    Jwt :: binary(),
    Jwk :: jose_jwk:key(),
    SupportedAlgorithms :: [binary()] | undefined,
    SupportedEncValues :: [binary()] | undefined
) ->
    {ok, binary()} | {error, no_supported_alg_or_key}.
encrypt(_Jwt, _Jwk, undefined, _SupportedEncValues) ->
    {error, no_supported_alg_or_key};
encrypt(_Jwt, _Jwk, _SupportedAlgorithms, undefined) ->
    {error, no_supported_alg_or_key};
encrypt(Jwt, Jwk, SupportedAlgorithms, SupportedEncValues) ->
    encrypt(Jwt, Jwk, SupportedAlgorithms, SupportedEncValues, SupportedEncValues).

-spec encrypt(
    Jwt :: binary(),
    Jwk :: jose_jwk:key(),
    SupportedAlgorithms :: [binary()],
    SupportedEncValues :: [binary()],
    AccEncValues :: [binary()]
) ->
    {ok, binary()} | {error, no_supported_alg_or_key}.
encrypt(_Jwt, _Jwk, [], _SupportedEncValues, _AccEncValues) ->
    {error, no_supported_alg_or_key};
encrypt(Jwt, Jwk, [_Algorithm | RestAlgorithms], SupportedEncValues, []) ->
    encrypt(Jwt, Jwk, RestAlgorithms, SupportedEncValues, SupportedEncValues);
encrypt(Jwt, Jwk, [Algorithm | _RestAlgorithms] = SupportedAlgorithms, SupportedEncValues, [
    EncValue | RestEncValues
]) ->
    EncryptionCallback = fun
        (#jose_jwk{fields = #{<<"use">> := <<"enc">>} = Fields} = Key) ->
            try
                JweParams0 = #{<<"alg">> => Algorithm, <<"enc">> => EncValue},
                JweParams =
                    case maps:get(<<"kid">>, Fields, undefined) of
                        undefined -> JweParams0;
                        Kid -> maps:put(<<"kid">>, Kid, JweParams0)
                    end,
                Jwe = jose_jwe:from_map(JweParams),
                {_Jws, Token} = jose_jwe:compact(jose_jwk:block_encrypt(Jwt, Jwe, Key)),
                {ok, Token}
            catch
                error:{not_supported, _Alg} -> error
            end;
        (_Key) ->
            error
    end,
    case evaluate_for_all_keys(Jwk, EncryptionCallback) of
        {ok, Token} -> {ok, Token};
        error -> encrypt(Jwt, Jwk, SupportedAlgorithms, SupportedEncValues, RestEncValues)
    end.

%% @private
-spec evaluate_for_all_keys(Jwk :: jose_jwk:key(), fun((jose_jwk:key()) -> {ok, Result} | error)) ->
    {ok, Result} | error
when
    Result :: term().
evaluate_for_all_keys(#jose_jwk{keys = {jose_jwk_set, Keys}}, Callback) ->
    lists:foldl(
        fun
            (_Key, {ok, Result}) ->
                {ok, Result};
            (Key, error) ->
                evaluate_for_all_keys(Key, Callback)
        end,
        error,
        Keys
    );
evaluate_for_all_keys(#jose_jwk{} = Jwk, Callback) ->
    Callback(Jwk).
