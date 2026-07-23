# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.HttpAdapterTest.Adapter do
  @behaviour :oidcc_http_adapter

  @impl true
  def request(method, request, http_options, request_options, config) do
    send(config.test_pid, {
      :adapter_request,
      method,
      request,
      http_options,
      request_options,
      config
    })

    {:ok,
     {{~c"HTTP/1.1", 200, ~c"OK"}, [{~c"content-type", ~c"application/json"}],
      ~s({"language":"elixir"})}}
  end
end

defmodule Oidcc.HttpAdapterTest do
  use ExUnit.Case, async: true

  test "an Elixir module can implement and be passed as the Erlang adapter behavior" do
    request = {"https://example.com", [{"accept", "application/json"}]}
    config = %{test_pid: self(), custom: %{language: :elixir}}

    assert {:ok, {{:json, %{"language" => "elixir"}}, [{~c"content-type", ~c"application/json"}]}} =
             :oidcc_http_util.request(
               :get,
               request,
               %{topic: [:oidcc, :elixir_http_adapter_test]},
               %{
                 timeout: 987,
                 http_adapter: {Oidcc.HttpAdapterTest.Adapter, config}
               }
             )

    assert_receive {
      :adapter_request,
      :get,
      ^request,
      [{:timeout, 987}],
      [{:body_format, :binary}],
      ^config
    }
  end
end
