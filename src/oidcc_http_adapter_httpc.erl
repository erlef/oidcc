%% SPDX-FileCopyrightText: 2023 Erlang Ecosystem Foundation
%% SPDX-License-Identifier: Apache-2.0

-module(oidcc_http_adapter_httpc).

-moduledoc "HTTP Client Adapter".

-behaviour(oidcc_http_adapter).

-export([request/5]).

-doc false.
-spec request(Method, Request, HttpOptions, RequestOptions, AdapterConfig) ->
    oidcc_http_adapter:response()
when
    Method :: oidcc_http_adapter:method(),
    Request :: oidcc_http_adapter:request(),
    HttpOptions :: oidcc_http_adapter:http_options(),
    RequestOptions :: oidcc_http_adapter:request_options(),
    AdapterConfig :: #{profile => atom() | pid()}.
request(Method, Request, HttpOptions, RequestOptions, AdapterConfig) ->
    Profile = maps:get(profile, AdapterConfig, default),
    httpc:request(Method, Request, HttpOptions, RequestOptions, Profile).
