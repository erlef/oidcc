# oidcc
OpenId Connect client library in Erlang.
OpenID Certified by Bas Wegh at SCC/KIT to the basic and configuration profile of the OpenID Connect protocol.

![OpenID Connect Certified Logo](./conformance/priv/static/oid_logo.png)
## The purpose
The purpose is to enable Erlang applications to rely on OpenId Connect Provider
for authentication and authorization purposes.

## Configuration
The oidcc library has some knobs to adjust the behaviour. The default behaviour is
as secure as possible while still being completely standard compliant.

For a first try mainly two settings are important:
 - cacertfile, this *MUST* be set if you want to use any provider which offers SSL connections.
 - cert_depth, you might need to increase this value for oidcc to accept your provider.

| Key | Description | Allowed Values (Default) |
| --- | ---- | ---- |
| cacertfile | The file containing all trusted Root CAs. On Debian based systems this usually is '/etc/ssl/certs/ca-certificates.crt', on red-hat based systems it is '/etc/pki/tls/certs/ca-bundle.crt'. You can also download the CA-file, which is extracted from mozilla, at the [curl site](https://curl.haxx.se/docs/caextract.html) and specify the path of its location. | path to a file (not set) |
| cert_depth | The number of signing steps allowed between the root and the server. A depth of '1' means the server certificate is directly signed by the CA. A chain of the Root CA, one intermediate CA and the server certificate results in a depth of '2'. | integer (1) |
| http_request_timeout | The time an http request may take until it is cancelled, in seconds | integer (300) |
| http_cache_duration | The duration in seconds to keep http results in cache, this is to reduce the load at the IdPs at request spikes coming from the same source. Only UserInfo and TokenIntrospection are cached, if enabled. This is especially useful for e.g. REST interfaces | integer, atom none (none) |
| http_cache_clean | The time in seconds after which the cleaning of the cache will be triggered (trigger happens only on writes) | integer (60) |
| provider_max_tries | The number of tries to perform http request to a provider for setup before giving up | integer (5) |
| scopes | The scope to request at the OpenID Connect provider | list of scopes ([openid]) |
| session_timeout | The time to keep a login session alive in ms | integer (30000) |
| support_none_algorithm | Wether the none algorithm should be supported. Oidcc allows the none algorithm only on direct communication with the provider. It is part of the OpenID Connect specification. The developer encourages to set this to 'false' | boolean (true) |

All these settings need to be set in the environment of oidcc.

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
  is handled by an http-handler for your web-server (see [oidcc_cowboy](https://github.com/indigo-dc/oidcc_cowboy) ).
* Additional configuration, using a map. possible configurations are:
  * name: a name for the provider, just some text (no functional usage)
  * description: a longer descriptive text (no functional usage)
  * client_id: the client id, if this is not given oidcc tries to dynamically register
  * client_secret: the client secret which has been generated during manual registration
  * request_scopes: the scopes to request by default when using this provider
  * registration_params: a map of parameter to use during the dynamic registration.
  * static_extend_url: a map used to create key/values in the redirection url


### Login Users
It is highly encouraged to implement the oidcc_client behaviour.
The oidcc_client behaviour expect two methods in your module:
 - login_succeeded/1 : Called when the login succeeded with the Token received
 - login_failed/2 : Called when the login failed with Error and Description

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
-behaviour(oidcc_client).

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
The possible updates depend on the web-module in use.
For oidcc_cowboy these are:
* {redirect, Path} : redirect the browser to the new path/url
* {cookie, Name, Data, Options} : create or delete a cookie
