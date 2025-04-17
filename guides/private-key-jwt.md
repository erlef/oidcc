# Using `private_key_jwt`

To use `private_key_jwt`, you need to provide the private key as a `JOSE.JWK`
wherever `client_context_options` can be provided.  

<!-- TODO: Remove once https://github.com/erlef/oidcc/issues/442 is fixed -->
You also need to set a dummy client secret for now, so that the client is considered
authenticated.

<!-- tabs-open -->

### Erlang

```erlang
%% Load key into jwk format
ClientJwk0 = jose_jwk:from_pem(<<"key_pem">>),

%% Set kid field, to make the computed jwts have a kid header
ClientJwk = ClientJwk0#jose_jwk{
    fields = #{<<"kid">> => <<"private_kid">>}
},

%% Refresh token when it expires
{ok, ClientContext} =
    oidcc_client_context:from_configuration_worker(
        Pid,
        <<"client_id">>,
        <<"dummy_client_secret">>,
        #{client_jwks => ClientJwk}
    ).
```

### Elixir

```elixir
# Load key into jwk format
# Set kid field, to make the computed jwts have a kid header
client_jwk =
  key
  |> JOSE.JWK.from_pem() 
  |> Map.put(:fields, %{"kid" => kid})

# Refresh token when it expires
{ok, client_context} =
    Oidcc.ClientContext.from_configuration_worker(
        pid,
        "client_id",
        "dummy_client_secret",
        %{client_jwks: client_jwk}
    ).
```

<!-- tabs-close -->
