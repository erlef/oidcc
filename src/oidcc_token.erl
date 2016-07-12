-module(oidcc_token).

-export([extract_token_map/1]).
-export([validate_token_map/3]).
-export([verify_access_token_map_hash/2]).
-export([validate_id_token/3]).

extract_token_map(Token) ->
    TokenMap = jsx:decode(Token, [return_maps]),
    IDToken = maps:get(<<"id_token">>, TokenMap, none),
    AccessToken = maps:get(<<"access_token">>, TokenMap, none),
    AccessExpire = maps:get(<<"expires_in">>, TokenMap, undefined),
    RefreshToken = maps:get(<<"refresh_token">>, TokenMap, none),
    #{id => #{token => IDToken, claims => undefined},
      access => #{token => AccessToken, expires => AccessExpire,
                  hash => undefined},
      refresh => #{token => RefreshToken}
     }.


validate_token_map(TokenMap, OpenIdProvider, Nonce) ->
    #{id := IdTokenMap,
      access := AccessTokenMap} = TokenMap,

    case validate_id_token_map(IdTokenMap, OpenIdProvider, Nonce) of
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
                      OpenIdProviderId, Nonce) ->
    case validate_id_token(IdToken, OpenIdProviderId, Nonce) of
        {ok, Claims} ->
            {ok, maps:put(claims, Claims, IdTokenMap)};
        Other -> Other
    end.

validate_id_token(IdToken, OpenIdProviderId, Nonce) ->
    try int_validate_id_token(IdToken, OpenIdProviderId, Nonce) of
        Claims -> {ok, Claims}
    catch
        Exception -> {error, Exception}
    end.

int_validate_id_token(IdToken, OpenIdProviderId, Nonce) ->
    {ok, OpInfo} = oidcc:get_openid_provider_info(OpenIdProviderId),
    {Header, Claims} = case ejwt:pre_parse_jwt(IdToken) of
                           #{ header := H, claims := C }  -> {H, C};
                           _ -> throw(not_a_jwt)
                       end,
    case contains_all_required_claims(Claims) of
        true -> ok;
        false -> throw(required_field_missing)
    end,
    Kid = maps:get(kid, Header, none),
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
    #{ iss := TokenIssuer} = Claims,
    case (Issuer =:= TokenIssuer) of
        true -> ok;
        false -> throw(wrong_issuer)
    end,

    % 3. The Client MUST validate that the aud (audience) Claim contains its
    % client_id value registered at the Issuer identified by the iss (issuer)
    % Claim as an audience. The aud (audience) Claim MAY contain an array with
    % more than one element. The ID Token MUST be rejected if the ID Token does
    % not list the Client as a valid audience, or if it contains additional
    % audiences not trusted by the Client.
    #{ aud := Audience} = Claims,
    case is_part_of_audience(ClientId, Audience) of
        true -> ok;
        false -> throw(not_in_audience)
    end,

    % 4. If the ID Token contains multiple audiences, the Client SHOULD verify
    % that an azp Claim is present.
    % 5.  If an azp (authorized party) Claim is present, the Client SHOULD
    % verify that its client_id is the Claim Value.
    case {is_list(Audience), maps:get(azp, Claims, undefined)} of
        {false, _} ->  ok;
        {true, ClientId} -> ok;
        {true, Azp} when is_binary(Azp) -> throw(azp_bad);
        {true, undefined} -> throw(azp_missing)
    end,


    % 7. The alg value SHOULD be the default of RS256 or the algorithm sent by
    % the Client in the id_token_signed_response_alg parameter during
    % Registration.
    #{ alg := Algo} = Header,
    case Algo == <<"RS256">> of
        true -> ok;
        false -> throw(not_rs256)
    end,

    % 6. If the ID Token is received via direct communication between the Client
    % and the Token Endpoint (which it is in this flow), the TLS server
    % validation MAY be used to validate the issuer in place of checking the
    % token signature. The Client MUST validate the signature of all other ID
    % Tokens according to JWS [JWS] using the algorithm specified in the JWT alg
    % Header Parameter. The Client MUST use the keys provided by the Issuer.
    %
    % 9. The current time MUST be before the time represented by the exp Claim.
    PubKey = get_needed_key(PubKeys, Kid),
    JWT = ejwt:parse_jwt(IdToken, PubKey, <<"JWT">>),
    case JWT of
        Claims -> ok;
        invalid -> throw(invalid_signature);
        expired -> throw(expired);
        _ -> throw(unknown_error)
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

    % 11. If a nonce value was sent in the Authentication Request, a nonce Claim
    % MUST be present and its value checked to verify that it is the same value
    % as the one that was % sent in the Authentication Request. The Client
    % SHOULD check the nonce value for replay attacks. The precise method for
    % detecting replay attacks is Client specific.
    NonceInToken = maps:get(nonce, Claims, undefined),
    case Nonce of
        NonceInToken -> ok;
        _ -> throw(wrong_nonce)
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
    maps:remove(nonce, Claims).

contains_all_required_claims(Jwt) ->
    Required = [iss, sub, aud, exp, iat, nonce],
    CheckKeys = fun(Key, _Val, List) ->
                        lists:delete(Key, List)
                end,
    Result =  maps:fold(CheckKeys, Required, Jwt),
    Result =:= [].

is_part_of_audience(ClientId, Audience) when is_binary(Audience) ->
    Audience == ClientId;
is_part_of_audience(ClientId, Audience) when is_list(Audience) ->
    lists:member(ClientId, Audience).



get_needed_key([], _) ->
    throw(no_key);
get_needed_key([#{key := Key}], none) ->
    Key;
get_needed_key(_, none) ->
    throw(too_many_keys);
get_needed_key([#{kid := KeyId, key := Key } |_], KeyId) ->
    Key;
get_needed_key([_Key | T], KeyId) ->
    get_needed_key(T, KeyId).

