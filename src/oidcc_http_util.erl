-module(oidcc_http_util).

-export([start_http/1]).
-export([async_http/5]).
-export([async_close/2]).
-export([sync_http/4]).
-export([uncompress_body_if_needed/2]).


sync_http(Method, Url, Header, InBody) ->
    {ok, ConPid, undefined, Path} = start_http(Url, false),
    {ok, _Protocol} = gun:await_up(ConPid),
    {ok, StreamRef} = async_http(Method, Path, Header, InBody, ConPid),
    {Status, Headers, Body} =
    case gun:await(ConPid, StreamRef) of
        {response, fin, S, H} ->
            {S, H, <<>>};
        {response, nofin, S, H} ->
            {ok, B1} = gun:await_body(ConPid, StreamRef),
            {ok, B} = uncompress_body_if_needed(B1, H),
            {S, H, B}
    end,
    ok = gun:shutdown(ConPid),
    {ok, #{status => Status, header => Headers, body => Body }}.

start_http(Url) ->
    start_http(Url,  true).

async_http(Method, Path, Header, Body, ConPid) ->
    StreamRef = case Method of
                    get -> gun:get(ConPid, Path, Header);
                    post -> gun:post(ConPid, Path, Header, Body)
                end,
    {ok, StreamRef}.

start_http(Url, Monitor) ->
    {ok, Config, Host, Port, Path} = parse_url(Url),
    {ok, ConPid} = gun:open(Host, Port, Config),
    MRef =  case Monitor of
                true -> monitor(process, ConPid);
                _ -> undefined
            end,
    {ok, ConPid, MRef, Path}.

async_close(Pid, MRef) ->
    true = demonitor(MRef),
    ok = gun:shutdown(Pid),
    ok.

uncompress_body_if_needed(Body, Header) when is_list(Header) ->
    Encoding = lists:keyfind(<<"content-encoding">>, 1, Header),
    uncompress_body_if_needed(Body, Encoding);
uncompress_body_if_needed(Body, false)  ->
    {ok, Body};
uncompress_body_if_needed(Body, {_, <<"gzip">>})  ->
    {ok, zlib:gunzip(Body)};
uncompress_body_if_needed(Body, {_, <<"deflate">>})  ->
    Z  = zlib:open(),
    ok = zlib:inflateInit(Z),
    {ok, zlib:inflate(Z, Body)};
uncompress_body_if_needed(_Body, {_, Compression})  ->
    erlang:error({unsupported_encoding, Compression}).


parse_url(Url) when is_binary(Url) ->
    [SchemeIn, HostPath] = binary:split(Url, [<<"://">>], [trim_all]),
    Scheme = list_to_binary(string:to_lower(binary_to_list(SchemeIn))),
    [HostPort, Path0] = binary:split(HostPath, [<<"/">>]),
    {Host, Port} = parse_host_port(HostPort, Scheme),
    Path = binary_to_list(<< <<"/">>/binary, Path0/binary>>),
    SchemeMap = scheme_to_map(Scheme),
    {ok, SchemeMap, Host, Port, Path}.

parse_host_port(HostPort, Scheme) ->
    HostPortList = binary:split(HostPort, [<<":">>]),
    return_host_port(HostPortList, Scheme).

return_host_port([HostBin], <<"http">>) ->
    Host = binary:bin_to_list(HostBin),
    {Host, 80};
return_host_port([HostBin], <<"https">>) ->
    Host = binary:bin_to_list(HostBin),
    {Host, 443};
return_host_port([HostBin, PortBin], _) ->
    Host = binary:bin_to_list(HostBin),
    Port = binary_to_integer(PortBin),
    {Host, Port}.

scheme_to_map(<<"http">>) ->
    #{};
scheme_to_map(<<"https">>) ->
    #{transport => ssl};
scheme_to_map(_) ->
    #{transport => ssl}.

