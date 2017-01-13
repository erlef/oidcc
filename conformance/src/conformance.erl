-module(conformance).

-export([
         run_test/2,
         start_debug/0,
         stop_debug/0
        ]).
-define(RPID,<<"oidcc.test.code">>).

run_test(<<"rp-response_type-code">> = Id, Req) ->
   test_rp_response_type_code(Id, Req);
run_test(<<"rp-scope-userinfo-claims">> = Id, Req) ->
    test_rp_scope_userinfo_claims(Id, Req);
run_test(<<"rp-nonce-invalid">>=Id, Req) ->
    test_rp_nonce_invalid(Id, Req);
run_test(<<"rp-token_endpoint-client_secret_basic">> = Id, Req) ->
    test_rp_token_endpoint_basic(Id, Req);
run_test(<<"rp-id_token-aud">> = Id, Req) ->
    test_rp_id_token(Id, Req);
run_test(<<"rp-id_token-kid-absent-single-jwks">> = Id, Req) ->
    test_rp_id_token(Id, Req);
run_test(<<"rp-userinfo-bad-sub-claim">> = Id, Req) ->
    test_rp_user_info(Id, Req);
run_test(TestId, Req) ->
    lager:error("unknown or unimplemented test ~p",[TestId]),
    redirect_to(<<"/">>, Req).



test_rp_response_type_code(TestId, Req) ->
    {ok, Id, _Pid} = dyn_reg_test(TestId),
    redirect_to_provider(Id, Req).



test_rp_scope_userinfo_claims(TestId, Req) ->
    %TODO: enable autofetch of userinfo
    Scopes = [openid, email, phone],
    lager:info("requesting scopes ~p", [Scopes]),
    {ok, Id, _Pid} = dyn_reg_test(TestId, Scopes),
    redirect_to_provider(Id, Req).

test_rp_nonce_invalid(TestId, Req) ->
    {ok, Id, _Pid} = dyn_reg_test(TestId),
    redirect_to_provider(Id, Req).

test_rp_token_endpoint_basic(TestId, Req) ->
    {ok, Id, _Pid} = dyn_reg_test(TestId),
    redirect_to_provider(Id, Req).

test_rp_id_token(TestId, Req) ->
    {ok, Id, _Pid} = dyn_reg_test(TestId),
    redirect_to_provider(Id, Req).

test_rp_user_info(TestId, Req) ->
    {ok, Id, _Pid} = dyn_reg_test(TestId),
    redirect_to_provider(Id, Req).


dyn_reg_test(TestId) ->
    dyn_reg_test(TestId, undefined).

dyn_reg_test(TestId, Scopes) ->
    Issuer = gen_issuer(TestId),
    dyn_reg(Issuer, TestId, Scopes).


dyn_reg(Issuer, Name, Scopes) ->
    {ok, Id, Pid} = oidcc:add_openid_provider(
                      undefined, Name, <<"description">>,
                     undefined, undefined, Issuer,
                     <<"https://localhost:8080/oidc">>,
                      Scopes
                                         ),
    lager:info("registration at ~p started with id ~p~n",[Issuer, Id]),
    case wait_for_provider_to_be_ready(Pid) of
        ok ->
            {ok, #{meta_data :=
                       #{client_id := ClientId,
                         client_secret := ClientSecret,
                         client_secret_expires_at := SecretExpire,
                         registration_access_token := RegAT
                        }
                  }} = oidcc:get_openid_provider_info(Pid),
            lager:info("successfully registered ~p at: ~p~n",[Id, Issuer]),
            lager:info(" client id: ~p~n",[ClientId]),
            lager:info(" client secret: ~p~n",[ClientSecret]),
            lager:info(" secret expires: ~p~n",[SecretExpire]),
            lager:info(" reg access token: ~p~n~n~n",[RegAT]),

            {ok, Id, Pid};
        Error -> Error
    end.

gen_issuer(TestId) ->
    Base = <<"https://rp.certification.openid.net:8080/">>,
    Slash = <<"/">>,
    << Base/binary, ?RPID/binary, Slash/binary, TestId/binary >>.




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

stop_debug() ->
    redbug:stop().

redirect_to_provider(Id, Req) ->
    Base = <<"/oidc?provider=">>,
    Url = << Base/binary, Id/binary >>,
    redirect_to(Url, Req).


redirect_to(Url, Req) ->
    lager:info("redirecting to ~p", [Url]),
    Header = [{<<"location">>, Url}],
    {ok, Req2} = cowboy_req:reply(302, Header, Req),
    Req2.
