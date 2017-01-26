# oidcc
OpenId Connect client library in Erlang

## The purpose
The purpose is to enable Erlang applications to rely on OpenId Connect Provider
for authentication purposes.


## Usage
### Setup an Openid Connect Provider
First an OpenId Connect Provider needs to be added, this is done by either
`oidcc:add_openid_provider/2` or `oidcc:add_openid_provider/3`.
The parameter are:
* Issuer or ConfigEndpoint: The url of the issuer or its configuration endpoint.
  Oidcc will figure out what it is and generate the needed configuration url.
  This url is used to receive the configuration and set up the client, no
  configuration needs to be done.
* LocalEndpoint: The local URL where the user will be redirected back to once
  logged in at the OpenId Connect provider, this MUST be the same as the path that
  is handled by an oidcc_client behaviour (see [oidcc_cowboy](https://github.com/indigo-dc/oidcc_cowboy) ).
* Additional configuration, using a map. possible configurations are:
  * name: a name for the provider, just some text (no functional usage)
  * description: a longer descriptive text (no functional usage)
  * client_id: the client id, if this is not given oidcc tries to dynamically register
  * client_secret: the client secret which has been generated during manual registration
  * request_scopes: the scopes to request by default when using this provider
  * registration_params: a map of parameter to use during the dynamic registration.


### Login Users
It is highly encouraged to implement the oidcc_client behaviour.

List of web-server modules that support the oidcc_client behaviour:
 * [oidcc_cowboy](https://github.com/indigo-dc/oidcc_cowboy) for cowboy

if you implemented an plugin/module for another web-server please let me know, so I can add it to the list above.


### you application code
This is a short description of the [basic_client example](https://github.com/indigo-dc/oidcc_cowboy/blob/master/example/basic_client)
First add an openid connect provider:
```
ConfigEndpoint = <<"https://some-provider.com">>,
LocalEndpoint = <<"http://localhost:8080/oidc">>,
Config = #{
  id => <<"someprovider">>,
  client_id => <<"1234">>,
  client_secret =>  <<"secret">>
 },
oidcc:add_openid_provider(ConfigEndpoint, LocalEndpoint, Config),
```

Second register your oidcc_client module:
```
oidcc_client:register(my_client)
```

Third start the web-server (in this example cowboy).
It is important, that you specify the correct path for the oidcc-server-module (oidcc_cowboy here).
In this example it is at '/oidc', that is why the LocalEndpoint above has the trailing /oidc.
```
Dispatch = cowboy_router:compile( [{'_',
  				[
   				 {"/", my_http, []},
   				 {"/oidc", oidcc_cowboy, []}
   				]}]),
{ok, _} = cowboy:start_http( http_handler
   		       , 100
   		       , [ {port, 8080} ]
   		       , [{env, [{dispatch, Dispatch}]}]
   		       ),
```

Your oidcc_client implementation is just a module with two functions:
```
-module(my_client)

-export([login_succeeded/1]).
-export([login_failed/2]).

login_succeeded(Token) ->
    io:format("~n~n*************************************~nthe user logged in with~n ~p~n", [Token]),
    % create e.g. a session and store it't id in a session to look it up on further usage
    SessionId = <<"123">>,
    CookieName = <<"MyClientSession">>,
    CookieData = SessionId,
    Path = <<"/">>,
    Updates = [
               {redirect, Path},
               {cookie, CookieName, CookieData, [{max_age, 30}]}
              ],
    {ok, Updates}.


login_failed(Error, Desc) ->
    io:format("~n~n*************************************~nlogin failed with~n ~p:~p~n", [Error, Desc]),
    Path = <<"/">>,
    Updates = [{redirect, Path}],
    {ok, Updates}.
```
The possible updates depend upon the web-module in use.
For oidcc_cowboy these are:
* {redirect, Path} : redirect the browser to the new path/url
* {cookie, Name, Data, Options} : create or delete a cookie
