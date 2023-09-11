# oidcc

[![Main Branch](https://github.com/Erlang-Openid/oidcc/actions/workflows/branch_main.yml/badge.svg?branch=main)](https://github.com/Erlang-Openid/oidcc/actions/workflows/branch_main.yml)
[![Module Version](https://img.shields.io/hexpm/v/oidcc.svg)](https://hex.pm/packages/oidcc)
[![Total Download](https://img.shields.io/hexpm/dt/oidcc.svg)](https://hex.pm/packages/oidcc)
[![License](https://img.shields.io/hexpm/l/oidcc.svg)](https://github.com/Erlang-OpenID/oidcc/blob/main/LICENSE)
[![Last Updated](https://img.shields.io/github/last-commit/Erlang-OpenID/oidcc.svg)](https://github.com/Erlang-OpenID/oidcc/commits/master)
[![Coverage Status](https://coveralls.io/repos/github/Erlang-Openid/oidcc/badge.svg?branch=main)](https://coveralls.io/github/Erlang-Openid/oidcc?branch=main)

OpenID Connect client library for Erlang.

<!-- TODO: Uncomment after certification -->
<!--
OpenID Certified by Jonatan Männchen at the Erlang Ecosystem Foundation for the
basic and configuration profile of the OpenID Connect protocol. For details,
check the [Conformance Documentation] (./conformance/HOWTO.md).

![OpenID Connect Certified Logo](https://openid.net/wp-content/uploads/2023/01/image.png))
-->

The refactoring for `v3` and the certification is funded as an
[Erlang Ecosystem Foundation](https://erlef.org/) stipend entered by the
[Security Working Group](https://erlef.org/wg/security).

## Setup

### Erlang

**directly**

```erlang
{ok, Pid} =
  oidcc_provider_configuration_worker:start_link(#{
    issuer => <<"https://accounts.google.com">>,
    name => {local, google_config_provider}
  }).
```

**via `supervisor`**

```erlang
-behaviour(supervisor).

%% ...

init(_Args) ->
  SupFlags = #{strategy => one_for_one},
  ChildSpecs = [#{id => oidcc_provider_configuration_worker,
                  start => {oidcc_provider_configuration_worker, start_link, [
                    #{issuer => "https://accounts.google.com",
                      name => {local, myapp_oidcc_config_provider}}
                  ]},
                  shutdown => brutal_kill}],
  {ok, {SupFlags, ChildSpecs}}.
```

### Elixir

**directly**

```elixir
{:ok, _pid} =
  Oidcc.ProviderConfiguration.Worker.start_link(%{
  issuer: "https://accounts.google.com/",
  name: Myapp.OidccConfigProvider
})
```

**via `Supervisor`**

```elixir
Supervisor.init([
  {Oidcc.ProviderConfiguration.Worker, %{
    issuer: "https://accounts.google.com",
    name: Myapp.OidccConfigProvider
  }}
], strategy: :one_for_one)
```

## Usage

### Companion libraries

`oidcc` offers integrations for various libraries:

<!-- TODO: Uncomment when available -->

<!-- - [`oidcc_cowboy`](https://hex.pm/packages/oidcc_cowboy) - Integrations for
  [`cowboy`](https://hex.pm/packages/cowboy) -->
- [`oidcc_plug`](https://hex.pm/packages/oidcc_plug) - Integrations for
  [`plug`](https://hex.pm/packages/plug) and
  [`phoenix`](https://hex.pm/packages/phoenix)
<!-- - [`phx_gen_oidcc`](https://hex.pm/packages/phx_gen_oidcc) - Setup Generator for
  [`phoenix`](https://hex.pm/packages/phoenix) -->

### Erlang

```erlang
%% Create redirect URI for authorization
{ok, RedirectUri} =
  oidcc:create_redirect_url(myapp_oidcc_config_provider,
                            <<"client_id">>,
                            <<"client_secret">>
                            #{redirect_uri: <<"https://example.com/callback"}),

%% Redirect user to `RedirectUri`

%% Retrieve `code` query / form param from redirect back

%% Exchange code for token
{ok, Token} =
  oidcc:retrieve_token(AuthCode,
                       myapp_oidcc_config_provider,
                       <<"client_id">>,
                       <<"client_secret">>,
                       #{redirect_uri => <<"https://example.com/callback">>}),

%% Load userinfo for token
{ok, Claims} =
  oidcc:retrieve_userinfo(Token,
                          myapp_oidcc_config_provider,
                          <<"client_id">>,
                          <<"client_secret">>,
                          #{}),

%% Load introspection for access token
{ok, Introspection} =
  oidcc:introspect_token(Token,
                         myapp_oidcc_config_provider,
                         <<"client_id">>,
                         <<"client_secret">>,
                         #{}),

%% Refresh token when it expires
{ok, RefreshedToken} =
  oidcc:refresh_token(Token,
                      myapp_oidcc_config_provider,
                      <<"client_id">>,
                      <<"client_secret">>,
                      #{}).
```

for more details, see https://hexdocs.pm/oidcc/oidcc.html

### Elixir

```elixir
# Create redirect URI for authorization
{:ok, redirect_uri} =
  Oidcc.create_redirect_url(
    Myapp.OidccConfigProvider,
    "client_id",
    "client_secret",
    %{redirect_uri: "https://example.com/callback"}
  )

# Redirect user to `redirect_uri`

# Retrieve `code` query / form param from redirect back

# Exchange code for token
{:ok, token} = Oidcc.retrieve_token(
  auth_code,
    Myapp.OidccConfigProvider,
  "client_id",
  "client_secret",
  %{redirect_uri: "https://example.com/callback"}
)

# Load userinfo for token
{:ok, Claims} = Oidcc.retrieve_userinfo(
  token,
  Myapp.OidccConfigProvider,
  "client_id",
  "client_secret",
  %{expected_subject: "sub"}
)

# Load introspection for access token
{:ok, introspection} = Oidcc.introspect_token(
  token,
  Myapp.OidccConfigProvider,
  "client_id",
  "client_secret"
)

# Refresh token when it expires
{:ok, refreshed_token} = Oidcc.refresh_token(
  token,
  Myapp.OidccConfigProvider,
  "client_id",
  "client_secret"
)
```

for more details, see https://hexdocs.pm/oidcc/Oidcc.html
