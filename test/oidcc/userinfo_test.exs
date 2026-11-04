# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.UserinfoTest do
  use ExUnit.Case, async: false

  alias Oidcc.ClientContext
  alias Oidcc.ProviderConfiguration
  alias Oidcc.Token
  alias Oidcc.Userinfo

  {:ok, example_metadata} =
    :oidcc
    |> Application.app_dir("priv/test/fixtures/example-metadata.json")
    |> File.read!()
    |> JOSE.decode()
    |> ProviderConfiguration.decode_configuration()

  @example_metadata example_metadata
  @example_jwks :oidcc
                |> Application.app_dir("priv/test/fixtures/jwk.pem")
                |> JOSE.JWK.from_pem_file()

  doctest Userinfo

  describe inspect(&Userinfo.retrieve/3) do
    test "works" do
      adapter =
        {Oidcc.TestHttpAdapter,
         %{
           request: fn :get, {"https://my.provider/userinfo", _headers} ->
             Oidcc.TestHttpAdapter.json_response(%{"sub" => "sub"})
           end
         }}

      client_context =
        ClientContext.from_manual(
          @example_metadata,
          @example_jwks,
          "client_id",
          "client_secret"
        )

      assert {:ok, %{"sub" => "sub"}} =
               Userinfo.retrieve(
                 %Token{
                   id: %Token.Id{
                     token: "id_token",
                     claims: %{"sub" => "sub"}
                   },
                   access: %Token.Access{token: "access_token", expires: :undefined},
                   refresh: %Token.Refresh{token: "refresh_token"},
                   scope: ["profile", "openid"]
                 },
                 client_context,
                 %{expected_subject: "sub", request_opts: %{http_adapter: adapter}}
               )
    end
  end
end
