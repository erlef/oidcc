# SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
# SPDX-License-Identifier: Apache-2.0

defmodule Oidcc.TestHttpAdapter do
  @moduledoc false

  @behaviour :oidcc_http_adapter

  @impl :oidcc_http_adapter
  def request(method, request, _http_options, _request_options, %{request: request_fun}),
    do: request_fun.(method, request)

  @spec json_response(body :: term()) :: :oidcc_http_adapter.response()
  def json_response(body),
    do:
      {:ok,
       {{~c"HTTP/1.1", 200, ~c"OK"}, [{~c"content-type", ~c"application/json"}],
        JOSE.encode(body)}}
end
