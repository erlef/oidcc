# oidcc
OpenId Connect client library in Erlang

## The purpose
The purpose is to enable Erlang applications to rely on OpenId Connect Provider
for authentication purposes.


## Quickstart / Demo
```
git clone https://github.com/indigo-dc/oidcc
cd oidcc/example/basic_client
make run
```
browse to [your example](http://localhost:8080) and log in.

## Usage 
### Setup an Openid Connect Provider 
First an OpenId Connect Provider needs to be added, this is done by either
`oidcc:add_openid_provider/6` or `oidcc:add_openid_provider/7`.
The parameter are:
* ID: the ID to give this provider, this is used to look up the provider again
  (only passed with `add_openid_provider/7`), if it is not given an Id will be
  generated.
* Name: the name you give this provider, no fuctionality
* Description: some description of this provider, no fuctionality
* ClientId: The OpenId Connect client id of your application, at this provider
* ClientSecret: The OpenId Connect client secret of your application 
* ConfigEndpoint: The configuration endpoint of the OpenId Connect provider.
  This url is used to receive the configuration and set up the client, no
  configuration needs to be done. 
* LocalEndpoint: The local URL where the user will be redirected back to once
  logged in at the OpenId Connect provider, this MUST be the same as the path the 
  `oidcc_http_handler` is running at, if you use the oidcc_client behaviour.


Example:
```Erlang
{ok, Id, Pid} = oidcc:add_openid_provider( <<"Google">>, 
                                           <<"The well known search giant">>,
                                           <<"234890982343">>,
                                           <<"my client secret">>,
                                           <<"https://accounts.google.com/.well-known/openid-configuration">>,
                                           <<"https://my.domain/oidc">>),
```
### Login Users: Using the Callbacks and Cowboy handler
Oidcc implements a cowboy handler for redirecting a user agent (browser) to an OpenId Connect provider and to handle its response automatically. The handler calls a callback, once finished.

The cowboy handler implements the steps described in the chapter "Login Users: by hand".

An example using the callbacks is in the examples/basic_client directory.

Basically three things need to be done:
 * Define a path to use for the cowboy handler
 * Implement the [oidcc_client behaviour](https://github.com/indigo-dc/oidcc/blob/master/src/oidcc_client.erl), see [`basic_client.erl`](https://github.com/indigo-dc/oidcc/blob/master/example/basic_client/src/basic_client.erl) for an example.
 * Register the implementation of the behaviour

#### Define a path to user for the cowboy handler
The path MUST be the same as the local endpoint provided when adding the OpenId Connect provider.
```
Dispatch = cowboy_router:compile( [{'_',
					[
					 {"/", basic_client_http, []},
                     %% add the oidcc_http_handler to a path
					 {"/oidc", oidcc_http_handler, []}
					]}]),
%% and start cowboy
{ok, _} = cowboy:start_http( http_handler
			       , 100
			       , [ {port, 8080} ]
			       , [{env, [{dispatch, Dispatch}]}]
			       )
```
#### Register the implementation of the behaviour 
```
{ok, ModuleId} = oidcc_client:register(<module name>).
```

#### Logging in ...
Now within your web application all you need to do is redirect the user agent 
to the `oidcc_http_handler` path passing the OpenId Connect provider id in the
query string, e.g. `/oidc?provider=123`.
It is also possible to specify the module to use by passing its id: 
`/oidc?provider=123&client_mod=456`.

Once the login has either succeeded or failed the registered module gets called.

During the login process the oidcc library ensures the user agent and the 
remote ip stay the same. 

These checks can be disabled by updating the oidcc settings:
```
%% disable user agent check
application:set_env(oidcc, check_user_agent, false).
%% disable remote ip check
application:set_env(oidcc, check_peer_ip, false).
```
### Login Users: by hand 
#### Create Redirection to Login Page 
Creating a redirection is done with one of the `oidcc:create_redirect_url`
functions. 
The parameters are:
* The Id of the OpenId Provider to use (result from the setup above).
* The scopes to request (if not given is set to openid).
* The state to receive when the user gets redirected back
* The nonce that should be contained in the JWT

The returned URL needs to be set as redirection in http reply.

Example:
```Erlang
{ok, Url} = oidcc:create_redirect_url( <<"234">>, 
                                       [openid, email],
                                       <<"my state">>,
                                       <<"random nonce, 4">>),
```

#### Retrieving the Tokens
When the user has been redirected back an auth code and ,if provided in the
redirection, the state will be given. For fetching the Tokens only the first
will be needed, yet the 2nd should be compared to the state used before.

For retrieving the function `oidcc:retrieve_token/2` will be used:
```Erlang
{ok, TokenData} = oidcc:retrieve_token(OpenProviderId,
                                       AuthCode),
```
The parameter are:
* OpenProviderId: The ID of the OpenId Connect Provider, returned during Setup
* AuthCode: The AuthCode code received when the User is redirected back.

#### Token Validation
The Received Token needs to be parsed and validated, for this purpose the
functions `oidcc:parse_and_validate_token` exist.

```Erlang
{ok, TokenMap} = oidcc:parse_and_validate_token(TokenData,
                                                OpenProviderId,
                                                Nonce),
```
The parameter are:
* TokenData: The binary Data received in the previous step
* OpenProviderId: The ID of the OpenId Connect Provider, returned during Setup
* Nonce: The Nonce given during the redirect creation (optional).

After this step the user is authenticated and the information about her can be
gathered by inspecting the `TokenMap`.

### Additional Operations
* To receive more information about the user the function `oidcc:retrive_user_info` can be used.
* To check e.g. the scopes of an access token the function `oidcc:introspect_token` can be used.


## LICENSE
This library was written as part of the INDIGO DataCould project and is realease
under the Apache License.



