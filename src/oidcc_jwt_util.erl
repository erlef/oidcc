%%%-------------------------------------------------------------------
%% @doc JWT Utilities
%% @end
%%%-------------------------------------------------------------------
-module(oidcc_jwt_util).

-include_lib("jose/include/jose_jwk.hrl").
-include_lib("jose/include/jose_jws.hrl").
-include_lib("jose/include/jose_jwt.hrl").

-export([client_secret_oct_keys/2]).
-export([refresh_jwks_fun/1]).
-export([verify_claims/2]).
-export([verify_signature/3]).

-export_type([claims/0]).
-export_type([error/0]).
-export_type([refresh_jwks_for_unknown_kid_fun/0]).

-type refresh_jwks_for_unknown_kid_fun() ::
    fun((Jwks :: jose_jwk:key(), Kid :: binary()) -> {ok, jose_jwk:key()} | {error, term()}).

-type error() :: no_matching_key | invalid_jwt_token | {no_matching_key_with_kid, Kid :: binary()}.

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
                    {false, _Jwt, _Jws} ->
                        {error, no_matching_key}
                end
        end
    catch
        error:{badarg, [_Token]} ->
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
    AllowedAlgorithms :: [binary()],
    ClientSecret :: binary().
client_secret_oct_keys(AllowedAlgorithms, ClientSecret) ->
    case
        lists:member(<<"HS256">>, AllowedAlgorithms) or
            lists:member(<<"HS384">>, AllowedAlgorithms) or
            lists:member(<<"HS512">>, AllowedAlgorithms)
    of
        true ->
            jose_jwk:from_oct(ClientSecret);
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
