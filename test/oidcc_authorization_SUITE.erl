-module(oidcc_authorization_SUITE).

-export([all/0]).
-export([create_redirect_url_inl_gov/1]).

-include_lib("stdlib/include/assert.hrl").

all() ->
    [create_redirect_url_inl_gov].

create_redirect_url_inl_gov(_Config) ->
    {ok, InlGovPid} =
        oidcc_provider_configuration_worker:start_link(#{
            issuer => <<"https://identity-preview.inl.gov">>
        }),

    {ok, ClientContext} = oidcc_client_context:from_configuration_worker(
        InlGovPid, <<"client_id">>, <<"client_secret">>
    ),

    {ok, Url} = oidcc_authorization:create_redirect_url(ClientContext, #{
        redirect_uri => <<"https://my.server/return">>
    }),

    ?assertMatch(
        <<"https://identity-preview.inl.gov/oauth2/v1/authorize?request=", _/binary>>,
        iolist_to_binary(Url)
    ),

    #{query := QueryString} = uri_string:parse(Url),
    QueryParams0 = uri_string:dissect_query(QueryString),
    QueryParams1 = lists:map(
        fun({Key, Value}) -> {list_to_binary(Key), list_to_binary(Value)} end, QueryParams0
    ),
    QueryParams = maps:from_list(QueryParams1),

    ?assertMatch(
        #{
            <<"client_id">> := <<"client_id">>,
            <<"redirect_uri">> := <<"https://my.server/return">>,
            <<"response_type">> := <<"code">>,
            <<"scope">> := <<"openid">>,
            <<"request">> := _
        },
        QueryParams
    ),

    ok.
