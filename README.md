# oidcc
OpenId Connect client library in Erlang

## The purpose
The purpose is to enable Erlang applications to rely on OpenId Connect Provider
for authentication purposes.


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
  logged in at the OpenId Connect provider, this MUST be the same as the path that
  is handled by an oidcc_client behaviour (see [oidcc_cowboy](https://github.com/indigo-dc/oidcc_cowboy) ).



### Login Users: by hand
It is recommended to use one implementation of the oidcc_client behaviour instead
of handlign this all 'by hand'.

List of oidcc_client implementations:
 * [oidcc_cowboy](https://github.com/indigo-dc/oidcc_cowboy) for cowboy

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
