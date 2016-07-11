-module(basic_client_app).
-behaviour(application).

-export([start/2]).
-export([stop/1]).

start(_, _) ->
    Id = <<"google">>,
    Name = <<"Google">>,
    Description = <<"you know it">>,
    ClientId = <<"65375832888-m99kcr0vu8qq95h588b1rhi52ei234qo.apps.googleusercontent.com">>,
    Secret = <<"MEfMXcaQtckJPBctTrAuSQkJ">>,
    ConfigEndpoint = <<"https://accounts.google.com/.well-known/openid-configuration">>,
    LocalEndpoint = <<"http://localhost:8080/oidc">>,
    oidcc:add_openid_provider(Id, Name, Description, ClientId, Secret, ConfigEndpoint,
			      LocalEndpoint),
    basic_client:init(),
    Dispatch = cowboy_router:compile( [{'_',
					[
					 {"/", basic_client_http, []},
					 {"/oidc", oidcc_http_handler, []}
					]}]),
    {ok, _} = cowboy:start_http( http_handler
			       , 100
			       , [ {port, 8080} ]
			       , [{env, [{dispatch, Dispatch}]}]
			       ),
    basic_client_sup:start_link().

stop(_) ->
    ok.
