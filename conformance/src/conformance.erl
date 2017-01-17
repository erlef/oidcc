-module(conformance).

-export([
         run_test/3,
         check_result/2,
         set_conf/2,
         get_conf/1,
         get_conf/2,
         start_debug/0,
         start_debug/1,
         stop_debug/0
        ]).

%%  *************
%%  *** TESTS ***
%%  *************


%% *** CODE - MANDATORY ***

%% rp-response_type-code
%% Make an authentication request using the Authorization Code Flow.
test_rp_response_type_code(Req) ->
    {ok, Id, _Pid} = dyn_reg_test(),
    redirect_to_provider(Id, Req).

%% An authentication response containing an authorization code.
check_rp_response_type_code(true, _) ->
    true;
check_rp_response_type_code(_, _) ->
    false.


%% rp-scope-userinfo-claims
%% Request claims using scope values.
test_rp_scope_userinfo_claims(Req) ->
    Params = maps:from_list(get_conf(params, [])),
    Scopes = case maps:get(<<"scp">>, Params, undefined) of
                 <<"profile">> -> [openid, profile];
                 <<"email">> -> [openid, email];
                 <<"address">> -> [openid, address];
                 <<"phone">> -> [openid, phone];
                 _ -> [openid, profile, email, address, phone]
             end,
    set_conf(scopes, Scopes),
    log("requesting scopes ~p", [Scopes]),
    {ok, Id, _Pid} = dyn_reg_test(#{scopes => Scopes}),
    redirect_to_provider(Id, Req).

%% A UserInfo Response containing the requested claims.
%% (following not applicable)
%% If no access token is issued (when using Implicit Flow with
%% response_type='id_token') the ID Token contains the requested claims.
check_rp_scope_userinfo_claims(true, #{user_info := UserInfo}) ->
    ProfileList = [name, family_name, given_name, middle_name,
                                 nickname, preferred_username, profile, picture,
                                 website, gender, birthdate, zoneinfo, locale,
                                 updated_at],
    EmailList = [email, email_verified],
    AddressList = [address],
    PhoneList = [phone_number, phone_number_verified],
    ProfileOk = check_scope(profile, ProfileList, UserInfo),
    EmailOk = check_scope(email, EmailList, UserInfo),
    AddressOk = check_scope(address, AddressList, UserInfo),
    PhoneOk = check_scope(phone, PhoneList, UserInfo),
    ProfileOk and EmailOk and AddressOk and PhoneOk;
check_rp_scope_userinfo_claims(_, _) ->
    false.


check_scope(Scope, ScopeList, UserInfo) ->
    Scopes = get_conf(scopes, []),
    Contains = fun( Key, _, Bool) ->
                       case lists:member(Key, ScopeList) of
                           true -> true;
                           _ -> Bool
                       end
               end,
    case lists:member(Scope, Scopes) of
        true ->
            maps:fold(Contains, false, UserInfo);
        _ ->
            true
    end.



%% rp-nonce-invalid
%% Pass a 'nonce' value in the Authentication Request.
%% Verify the 'nonce' value returned in the ID Token.
test_rp_nonce_invalid(Req) ->
    {ok, Id, _Pid} = dyn_reg_test(),
    redirect_to_provider(Id, Req).

%% Identify that the 'nonce' value in the ID Token is invalid and
%% reject the ID Token.
check_rp_nonce_invalid(false, {internal, {token_invalid, {error, wrong_nonce}}}) ->
    true;
check_rp_nonce_invalid(_, _) ->
    false.

%% rp-token_endpoint-client_secret_basic
%%
%% Use the 'client_secret_basic' method to authenticate at the
%% Authorization Server when using the token endpoint.
test_rp_token_endpoint_basic(Req) ->
    {ok, Id, _Pid} = dyn_reg_test(),
    redirect_to_provider(Id, Req).

%% A Token Response, containing an ID token.
check_rp_token_endpoint_basic(true, #{id := #{token := IdToken}})
    when is_binary(IdToken), byte_size(IdToken) > 5 ->
    true;
check_rp_token_endpoint_basic(_, _) ->
    false.

%% rp-id_token-aud
%%
%% Request an ID token and compare its aud value
%% to the Relying Party's 'client_id'.
test_rp_id_token(Req) ->
    {ok, Id, _Pid} = dyn_reg_test(),
    redirect_to_provider(Id, Req).

%% Identify that the 'aud' value is missing or doesn't match the 'client_id'
%% and reject the ID Token after doing ID Token validation.
check_rp_id_token_aud(false,
                      {internal, {token_invalid,{error,not_in_audience}}}) ->
    true;
check_rp_id_token_aud(_, _) ->
    false.


%% rp-id_token-kid-absent-single-jwks
%%
%% Request an ID token and verify its signature using the keys
%% provided by the Issuer.
%%
%% Use the single key published by the Issuer to verify the ID Tokens signature
%% and accept the ID Token after doing ID Token validation.
check_rp_id_token_absent_single_jwks(true, _TokenMap) ->
    true;
check_rp_id_token_absent_single_jwks(_, _) ->
    false.

%% rp-id_token-sig-none
%%
%% Use Code Flow and retrieve an unsigned ID Token.
%%
%% Accept the ID Token after doing ID Token validation.
check_rp_id_token_sig_none(true, _TokenMap) ->
    true;
check_rp_id_token_sig_none(_, _) ->
    false.

%% rp-id_token-issuer-mismatch
%%
%% Request an ID token and verify its 'iss' value.
%%
%% Identify the incorrect 'iss' value and reject the ID Token after doing ID Token validation.
check_rp_id_token_issuer_mismatch(false, {internal, {token_invalid, {error, {wrong_issuer, _, _}}}}) ->
    true;
check_rp_id_token_issuer_mismatch(_, _) ->
    false.

%% rp-id_token-kid-absent-multiple-jwks
%%
%% Request an ID token and verify its signature using the keys provided by
%% the Issuer.
%%
%% dentify that the 'kid' value is missing from the JOSE header and that the
%% Issuer publishes multiple keys in its JWK Set document (referenced by
%% 'jwks_uri').
%% The RP can do one of two things;
%% reject the ID Token since it can not by using the kid determined which
%% key to use to verify the signature. <- solution used here
%%
%% Or it can just test all possible keys and hit upon one that works,
%% which it will in this case.
check_rp_id_token_kid_absent_multiple(false, {internal, {token_invalid, {error, too_many_keys}}}) ->
    true;
check_rp_id_token_kid_absent_multiple(_, _) ->
    false.

%% rp-id_token-bad-sig-rs256
%%
%% Request an ID token and verify its signature using the keys provided by
%% the Issuer.
%%
%% Identify the invalid signature and reject the ID Token after doing
%% ID Token validation.
check_rp_id_token_bad_sig(false, {internal, {token_invalid, {error, invalid_signature}}}) ->
    true;
check_rp_id_token_bad_sig(_, _) ->
    false.

%% rp-id_token-iat
%%
%% Request an ID token and verify its 'iat' value.
%%
%% dentify the missing 'iat' value and reject the ID Token after doing
%% ID Token validation.
check_rp_id_token_iat(false, {internal, {token_invalid, {error, {required_fields_missing, [iat]}}}}) ->
    true;
check_rp_id_token_iat(_, _) ->
    false.


%% rp-id_token-sig-rs256
%%
%% Request an signed ID Token. Verify the signature on the ID Token using the
%% keys published by the Issuer.
%%
%% Accept the ID Token after doing ID Token validation.
check_rp_id_token_sig_rs256(true, #{ id := #{token := IdToken}} )
 when is_binary(IdToken), byte_size(IdToken) > 3 ->
    case erljwt:pre_parse_jwt(IdToken) of
        #{header := #{alg := Algo}} ->
            log("signature algorithm used is: ~p~n",[Algo]),
            Algo /= <<"none">>;
        _ ->
            false
    end;
check_rp_id_token_sig_rs256(_, _) ->
    false.

%% rp-id_token-sub
%%
%%Request an ID token and verify it contains a sub value.
%%
%% Identify the missing 'sub' value and reject the ID Token.
check_rp_id_token_sub(false, {internal, {token_invalid, {error, {required_fields_missing, [sub]}}}}) ->
    true;
check_rp_id_token_sub(_, _) ->
    false.

%% rp-userinfo-bad-sub-claim
%%
%% Make a UserInfo Request and verify the 'sub' value of the UserInfo Response
%% by comparing it with the ID Token's 'sub' value.
test_rp_user_info(Req) ->
    {ok, Id, _Pid} = dyn_reg_test(),
    redirect_to_provider(Id, Req).

%% Identify the invalid 'sub' value and reject the UserInfo Response.
check_rp_user_info_bad_sub_claim(true, TokenMap) ->
    %% ensure the error is due to invalid sub value
    #{ user_info := UserInfo } = TokenMap,
    length( maps:to_list(UserInfo) ) == 0;
check_rp_user_info_bad_sub_claim(_, _) ->
    false.



%% rp-userinfo-bearer-body
%%
%% Pass the access token as a form-encoded body parameter while doing the
%% UserInfo Request.
test_rp_user_info_bearer_body(Req) ->
    {ok, Id, _Pid} = dyn_reg_test(),
    redirect_to_provider(Id, Req).

%% A UserInfo Response.
check_rp_user_info_bearer_body(true, TokenMap) ->
    #{ user_info := UserInfo } = TokenMap,
    length( maps:to_list(UserInfo) ) /= 0;
check_rp_user_info_bearer_body(_, _) ->
    false.

%% rp-userinfo-bearer-header
%%
%% Pass the access token using the "Bearer" authentication scheme while doing
%% the UserInfo Request.
%%
%% A UserInfo Response.
check_rp_user_info_bearer_header(true, TokenMap) ->
    #{ user_info := UserInfo } = TokenMap,
    length( maps:to_list(UserInfo) ) /= 0;
check_rp_user_info_bearer_header(_, _) ->
    false.

%% *** CODE - OPTIONAL ***
%% *** CONFIGURATION - MANDATORY ***
%% *** CONFIGURATION - OPTIONAL ***
%% *** DYNAMIC - OPTIONAL ***




%% *****************************************************************************
%% functions to handle tests
%%

-define(TESTS, [
                {<<"rp-response_type-code">>,
                 fun test_rp_response_type_code/1,
                 fun check_rp_response_type_code/2},
                {<<"rp-scope-userinfo-claims">>,
                 fun test_rp_scope_userinfo_claims/1,
                  fun check_rp_scope_userinfo_claims/2},
                {<<"rp-nonce-invalid">>,
                 fun test_rp_nonce_invalid/1,
                 fun check_rp_nonce_invalid/2 },
                {<<"rp-token_endpoint-client_secret_basic">>,
                 fun test_rp_token_endpoint_basic/1,
                 fun check_rp_token_endpoint_basic/2 },
                {<<"rp-id_token-aud">> ,
                 fun test_rp_id_token/1,
                 fun check_rp_id_token_aud/2 },
                {<<"rp-id_token-kid-absent-single-jwks">>,
                 fun test_rp_id_token/1,
                 fun check_rp_id_token_absent_single_jwks/2 },
                {<<"rp-id_token-sig-none">>,
                 fun test_rp_id_token/1,
                 fun check_rp_id_token_sig_none/2},
                {<<"rp-id_token-issuer-mismatch">>,
                 fun test_rp_id_token/1,
                 fun check_rp_id_token_issuer_mismatch/2},
                {<<"rp-id_token-kid-absent-multiple-jwks">>,
                 fun test_rp_id_token/1,
                 fun check_rp_id_token_kid_absent_multiple/2},
                {<<"rp-id_token-bad-sig-rs256">>,
                 fun test_rp_id_token/1,
                 fun check_rp_id_token_bad_sig/2},
                {<<"rp-id_token-iat">>,
                 fun test_rp_id_token/1,
                 fun check_rp_id_token_iat/2},
                {<<"rp-id_token-sig-rs256">>,
                 fun test_rp_id_token/1,
                 fun check_rp_id_token_sig_rs256/2},
                {<<"rp-id_token-sub">>,
                 fun test_rp_id_token/1,
                 fun check_rp_id_token_sub/2},

                {<<"rp-userinfo-bad-sub-claim">>,
                 fun test_rp_user_info/1,
                 fun check_rp_user_info_bad_sub_claim/2 },
                {<<"rp-userinfo-bearer-body">>,
                 fun test_rp_user_info_bearer_body/1,
                 fun check_rp_user_info_bearer_body/2 },
                {<<"rp-userinfo-bearer-header">>,
                 fun test_rp_user_info/1,
                 fun check_rp_user_info_bearer_header/2 }
               ]).

run_test(Id, Params, Req) ->
    case lists:keyfind(Id, 1, ?TESTS) of
        {Id, TestFun, _} ->
            register_test(Id, Params),
            TestFun(Req);
        _ ->
            lager:error("unknown or unimplemented test ~p",[Id]),
            redirect_to(<<"/">>, Req)
    end.




check_result(LoggedIn, TokenOrError) ->
    {ok, Id} = get_test_id(),
    case LoggedIn of
        true ->
            log("User logged in ~p~n", [TokenOrError]);
        false ->
            log("User not logged in ~p~n", [TokenOrError])
    end,
    case lists:keyfind(Id, 1, ?TESTS) of
        {Id, _, CheckFun} ->
            case CheckFun(LoggedIn, TokenOrError) of
                true ->
                    log("*** ~p passed ***", [Id]);
                _ ->
                    log("*** ~p FAILED ***", [Id])
            end ;
        _ ->
            lager:error("unknown or unimplemented check ~p",[Id]),
            log("*** ~p FAILED ***")
    end.



dyn_reg_test() ->
    dyn_reg_test(#{}).

dyn_reg_test(Options) ->
    Scopes = maps:get(scopes, Options, undefined),
    {ok, TestId} = get_test_id(),
    Issuer = gen_issuer(TestId),
    dyn_reg(Issuer, TestId, Scopes).

dyn_reg(Issuer, Name, Scopes) ->
    {ok, Id, Pid} = oidcc:add_openid_provider(
                      undefined, Name, <<"description">>,
                     undefined, undefined, Issuer,
                     <<"https://localhost:8080/oidc">>,
                      Scopes
                                         ),
    log("registration at ~p started with id ~p~n",[Issuer, Id]),
    case wait_for_provider_to_be_ready(Pid) of
        ok ->
            {ok, Config} = oidcc:get_openid_provider_info(Pid),
            #{meta_data :=
                  #{client_id := ClientId,
                    client_secret := ClientSecret,
                    client_secret_expires_at := SecretExpire,
                    registration_access_token := RegAT
                   }
             } =  Config,
            log("successfully registered ~p at: ~p~n",[Id, Issuer]),
            log(" client id: ~p~n",[ClientId]),
            log(" client secret: ~p~n",[ClientSecret]),
            log(" secret expires: ~p~n",[SecretExpire]),
            log(" reg access token: ~p~n~n~n",[RegAT]),
            log(" complete config: ~p",[Config]),

            {ok, Id, Pid};
        Error -> Error
    end.

gen_issuer(TestId) ->
    Base = <<"https://rp.certification.openid.net:8080/">>,
    Slash = <<"/">>,
    RpId = get_rp_id(),
    << Base/binary, RpId/binary, Slash/binary, TestId/binary >>.




wait_for_provider_to_be_ready(Pid) ->
    wait_for_provider_to_be_ready(Pid, 100).

wait_for_provider_to_be_ready(_Pid, 0) ->
    {error, timeout};
wait_for_provider_to_be_ready(Pid, Num) ->
    case oidcc_openid_provider:is_ready(Pid) of
        false ->
            timer:sleep(100),
            wait_for_provider_to_be_ready(Pid, Num-1);
        true ->
            ok
    end.


start_debug() ->
    ModuleList = ["oidcc_openid_provider"],
    Options = [{time, 60000}, {msgs, 10000}],
    redbug:start(ModuleList, Options).

start_debug(ModuleList) ->
    Options = [{time, 60000}, {msgs, 10000}],
    redbug:start(ModuleList, Options).

stop_debug() ->
    redbug:stop().

redirect_to_provider(Id, Req) ->
    Base = <<"/oidc?provider=">>,
    Url = << Base/binary, Id/binary >>,
    redirect_to(Url, Req).


redirect_to(Url, Req) ->
    log("redirecting to ~p~n", [Url]),
    Header = [{<<"location">>, Url}],
    {ok, Req2} = cowboy_req:reply(302, Header, Req),
    Req2.


register_test(Id, Params) ->
    set_conf(test_id, Id),
    set_conf(params, Params),
    CurrentTime = cowboy_clock:rfc1123(),
    log("starting test ~p at ~p~n",[Id, CurrentTime]).

get_test_id() ->
    get_conf(test_id).

get_rp_id() ->
    get_conf(rp_id, <<"oidcc.temp.code">>).

set_conf(Key, Value) ->
    application:set_env(?MODULE, Key, Value).

get_conf(Key) ->
    application:get_env(?MODULE, Key).

get_conf(Key, Default) ->
    application:get_env(?MODULE, Key, Default).


log(Format, Args) ->
    Msg = io_lib:format(Format, Args),
    log(Msg).

log(Msg) ->
    {ok, TestId} = get_test_id(),
    {ok, LogDir} = get_conf(log_dir),
    Ext = <<".txt">>,
    FileName = << LogDir/binary, TestId/binary, Ext/binary >>,
    ok = file:write_file(FileName, Msg, [append]),
    lager:info(Msg).
