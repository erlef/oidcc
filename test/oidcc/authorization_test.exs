# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.AuthorizationTest do
  use ExUnit.Case, async: true

  alias Oidcc.Authorization

  doctest Authorization

  describe inspect(&Authorization.create_redirect_url/2) do
    test "works" do
      pid =
        start_supervised!(
          {Oidcc.ProviderConfiguration.Worker, %{issuer: "https://accounts.google.com"}}
        )

      {:ok, client_context} =
        Oidcc.ClientContext.from_configuration_worker(
          pid,
          "client_id",
          "client_secret"
        )

      assert {:ok, _redirect_uri} =
               Authorization.create_redirect_url(
                 client_context,
                 %{redirect_uri: "https://my.server/return"}
               )
    end
  end

  describe inspect(&Authorization.validate_iss_parameter/2) do
    setup do
      pid =
        start_supervised!(
          {Oidcc.ProviderConfiguration.Worker, %{issuer: "https://accounts.google.com"}}
        )

      {:ok, client_context} =
        Oidcc.ClientContext.from_configuration_worker(pid, "client_id", "client_secret")

      %{client_context: client_context}
    end

    test "accepts the provider issuer", %{client_context: client_context} do
      assert :ok =
               Authorization.validate_iss_parameter("https://accounts.google.com", client_context)
    end

    test "rejects another issuer", %{client_context: client_context} do
      assert {:error, {:invalid_iss_parameter, "https://attacker.example.com"}} =
               Authorization.validate_iss_parameter(
                 "https://attacker.example.com",
                 client_context
               )
    end

    test "rejects a missing iss when the provider advertises it", %{
      client_context: client_context
    } do
      client_context = %{
        client_context
        | provider_configuration: %{
            client_context.provider_configuration
            | authorization_response_iss_parameter_supported: true
          }
      }

      assert {:error, :missing_iss_parameter} =
               Authorization.validate_iss_parameter(nil, client_context)
    end
  end
end
