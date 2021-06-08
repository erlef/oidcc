-module(oidcc_token).

-export([extract_token_map/2]).
-export([introspect_token_map/2]).
-export([validate_token_map/3]).
-export([validate_token_map/4]).
-export([verify_access_token_map_hash/2]).
-export([validate_id_token/3]).
-export([validate_id_token/4]).

extract_token_map(Token, OrgScope) ->
    TokenMap = jsone:decode(Token, [{object_format, map}]),
    IDToken = maps:get(<<"id_token">>, TokenMap, none),
    AccessToken = maps:get(<<"access_token">>, TokenMap, none),
    AccessExpire = maps:get(<<"expires_in">>, TokenMap, undefined),
    RefreshToken = maps:get(<<"refresh_token">>, TokenMap, none),
    Scope = maps:get(<<"scope">>, TokenMap, OrgScope),
    #{id => #{token => IDToken, claims => undefined},
      access => #{token => AccessToken, expires => AccessExpire,
                  hash => undefined},
      refresh => #{token => RefreshToken},
      scope => scope_map(Scope)
     }.

introspect_token_map(Token, ThisClientId) ->
    TokenMap = jsone:decode(Token, [{object_format, map}]),
    Active = case maps:get(<<"active">>, TokenMap, undefined) of
                 true -> true;
                 _ -> false

             end,
    Scope = maps:get(<<"scope">>, TokenMap, <<"">>),
    ClientId = maps:get(<<"client_id">>, TokenMap, undefined),
    SameClientId = (ClientId == ThisClientId),
    Username = maps:get(<<"username">>, TokenMap, undefined),
    Exp = maps:get(<<"exp">>, TokenMap, undefined),
    #{
       active => Active,
       scope => scope_map(Scope),
       client_id => #{ id => ClientId,
                       same => SameClientId
                     },
       username => Username,
       exp => Exp
     }.


scope_map(Scope) ->
    #{ scope => Scope,
       list => binary:split(Scope, [<<" ">>], [trim_all, global])
       }.


validate_token_map(TokenMap, OpenIdProvider, Nonce) ->
    validate_token_map(TokenMap, OpenIdProvider, Nonce, false).

validate_token_map(TokenMap, OpenIdProvider, Nonce, AllowNone) ->
    #{id := IdTokenMap,
      access := AccessTokenMap} = TokenMap,

    case validate_id_token_map(IdTokenMap, OpenIdProvider, Nonce, AllowNone) of
        {ok, NewIdTokenMap} ->
            NewAccessTokenMap = verify_access_token_map_hash(AccessTokenMap,
                                                             NewIdTokenMap),
            TokenMap1 = maps:put(id, NewIdTokenMap, TokenMap),
            Result = maps:put(access, NewAccessTokenMap, TokenMap1),
            {ok, Result};
        Other ->
            Other
    end.


verify_access_token_map_hash(AccessTokenMap, IdTokenMap) ->
    try int_verify_access_token_hash(AccessTokenMap, IdTokenMap) of
        Result -> Result
    catch
        _:_ -> maps:put(hash, internal_error, AccessTokenMap)
    end.

int_verify_access_token_hash(#{token := AccessToken} = Map,
                             #{claims := Claims}) ->
    << BinHash:16/binary, _Rest/binary>> = crypto:hash(sha256, AccessToken),
    Hash = base64url:encode(BinHash),
    Result = case maps:get(at_hash, Claims, undefined) of
        undefined -> no_hash;
        Hash ->  verified;
        _OtherHash -> bad_hash
    end,
    maps:put(hash, Result, Map).

validate_id_token_map(#{token := IdToken} = IdTokenMap,
                      OpenIdProviderId, Nonce, AllowNone) ->
    case validate_id_token(IdToken, OpenIdProviderId, Nonce, AllowNone) of
        {ok, Claims} ->
            {ok, maps:put(claims, Claims, IdTokenMap)};
        Other -> Other
    end.

validate_id_token(IdToken, OpenIdProviderId, Nonce) ->
    validate_id_token(IdToken, OpenIdProviderId, Nonce, false).

validate_id_token(IdToken, OpenIdProviderId, Nonce, AllowNone) ->
    try int_validate_id_token(IdToken, OpenIdProviderId, Nonce, AllowNone) of
        Claims -> {ok, Claims}
    catch
        Exception -> {error, Exception}
    end.

int_validate_id_token(IdToken, OpenIdProviderId, Nonce, AllowNone)
    when is_binary(IdToken), byte_size(IdToken) > 5->
    {ok, OpInfo} = oidcc:get_openid_provider_info(OpenIdProviderId),
    #{ issuer := Issuer,
       client_id := ClientId,
       keys := PubKeys
     } = OpInfo,

    % 1. If the ID Token is encrypted, decrypt it using the keys and algorithms
    % that the Client specified during Registration that the OP was to use to
    % encrypt the ID Token. If encryption was negotiated with the OP at
    % Registration time and the ID Token is not encrypted, the RP SHOULD reject
    % it.
    % TODO: implement later if needed, not for now

    % 2.  The Issuer Identifier for the OpenID Provider (which is typically
    % obtained during Discovery) MUST exactly match the value of the iss
    % (issuer) Claim.

    % 3. The Client MUST validate that the aud (audience) Claim contains its
    % client_id value registered at the Issuer identified by the iss (issuer)
    % Claim as an audience. The aud (audience) Claim MAY contain an array with
    % more than one element. The ID Token MUST be rejected if the ID Token does
    % not list the Client as a valid audience, or if it contains additional
    % audiences not trusted by the Client.

    % 11. If a nonce value was sent in the Authentication Request, a nonce Claim
    % MUST be present and its value checked to verify that it is the same value
    % as the one that was % sent in the Authentication Request. The Client
    % SHOULD check the nonce value for replay attacks. The precise method for
    % detecting replay attacks is Client specific.
    %% NonceInToken = maps:get(nonce, Claims, undefined),
    %% case Nonce of
    %%     NonceInToken -> ok;
    %%     any -> ok;
    %%     _ -> throw(wrong_nonce)
    %% end,

    ExpClaims0 = #{aud => ClientId,
                  iss => Issuer
                 },

    ExpClaims = case Nonce of
                    any ->
                        ExpClaims0;
                    Bin when is_binary(Bin) ->
                        maps:put(nonce, Nonce, ExpClaims0)
                end,

    % 6. If the ID Token is received via direct communication between the Client
    % and the Token Endpoint (which it is in this flow), the TLS server
    % validation MAY be used to validate the issuer in place of checking the
    % token signature. The Client MUST validate the signature of all other ID
    % Tokens according to JWS [JWS] using the algorithm specified in the JWT alg
    % Header Parameter. The Client MUST use the keys provided by the Issuer.
    %
    % 7. The alg value SHOULD be the default of RS256 or the algorithm sent by
    % the Client in the id_token_signed_response_alg parameter during
    % Registration.

    %% #{ alg := Algo} = Header,
    DefaultAlgorithms = [rs256],
    AcceptedAlgorithms =
        case AllowNone
            and application:get_env(oidcc, support_none_algorithm, true) of
            true ->
                [none | DefaultAlgorithms];
            _ ->
                DefaultAlgorithms
        end,

    % 8. If the JWT alg Header Parameter uses a MAC based algorithm such as
    % HS256, HS384, or HS512, the octets of the UTF-8 representation of the
    % client_secret corresponding to the client_id contained in the aud
    % (audience) Claim are used as the key to validate the signature. For MAC
    % based algorithms, the behavior is unspecified if the aud is multi-valued
    % or if an azp value is present that is different than the aud value.
    %
    % won't be used for now, so not implemented

    % 10. The iat Claim can be used to reject tokens that were issued too far
    % away from the current time, limiting the amount of time that nonces need
    % to be stored to prevent attacks. The acceptable range is Client specific.
    % TODO: maybe in the future, not for now


    % 9. The current time MUST be before the time represented by the exp Claim.
    Claims = case verify_jwt(IdToken, AcceptedAlgorithms, ExpClaims, PubKeys,
                             OpenIdProviderId) of
                           #{claims := C} -> C;
                           invalid -> throw(invalid_signature);
                           Error  -> throw(Error)
                       end,

    case list_missing_required_claims(Claims) of
        [] -> ok;
        Missing -> throw({required_fields_missing, Missing})
    end,


    % 4. If the ID Token contains multiple audiences, the Client SHOULD verify
    % that an azp Claim is present.
    % 5.  If an azp (authorized party) Claim is present, the Client SHOULD
    % verify that its client_id is the Claim Value.
    #{ aud := Audience} = Claims,
    case {has_other_audience(ClientId, Audience),
          maps:get(azp, Claims, undefined)} of
        {false, _} ->  ok;
        {true, ClientId} -> ok;
        {true, Azp} when is_binary(Azp) -> throw(azp_bad);
        {true, undefined} -> throw(azp_missing)
    end,


    % 12. If the acr Claim was requested, the Client SHOULD check that the
    % asserted Claim Value is appropriate. The meaning and processing of acr
    % Claim Values is out of scope for this specification. If the acr Claim was
    % requested, the Client SHOULD check that the asserted Claim Value is
    % appropriate. The meaning and processing of acr Claim Values is out of
    % scope for this specification.
    % TODO: check what for

    % 13. If the auth_time Claim was requested, either through a specific
    % request for this Claim or by using the max_age parameter, the Client
    % SHOULD check the auth_time Claim value and request re-authentication if it
    % determines too much time has elapsed since the last End-User
    % authentication.
    % TODO: maybe later, not for now

    % delete the nonce before handing it out, only needs space as it has been
    % checked by now
    maps:remove(nonce, Claims);
int_validate_id_token(_IdToken, _OpenIdProviderId, _Nonce, _AllowNone) ->
    throw(no_id_token).

list_missing_required_claims(Jwt) ->
    Required = [iss, sub, aud, exp, iat, nonce],
    CheckKeys = fun(Key, _Val, List) ->
                        lists:delete(Key, List)
                end,
    maps:fold(CheckKeys, Required, Jwt).

has_other_audience(ClientId, Audience) when is_binary(Audience) ->
    Audience /= ClientId;
has_other_audience(ClientId, Audience) when is_list(Audience) ->
    length(lists:delete(ClientId, Audience)) >= 1.


verify_jwt(IdToken, AllowedAlgos, ExpClaims, Pubkeys, ProviderId) ->
    case {erljwt:validate(IdToken, AllowedAlgos, ExpClaims, Pubkeys),
          ProviderId} of
        {{error, _}, undefined} ->
            invalid;
        {{error, Reason}, ProviderId}
          when Reason==invalid; Reason==no_key_found ->
            %% it might be the case that our keys expired ...
            %% so refetch them
            NewPubKeys = refetch_keys(ProviderId),
            verify_jwt(IdToken, AllowedAlgos, ExpClaims, NewPubKeys, undefined);
        {{ok, Jwt}, _Provider} when is_map(Jwt)->
            Jwt;
        {{error, Error}, _} ->
            Error
    end.


refetch_keys(ProviderId) ->
    {ok, Pid} = oidcc_openid_provider_mgr:get_openid_provider(ProviderId),
    {ok, Keys} = oidcc_openid_provider:update_and_get_keys(Pid),
    Keys.
