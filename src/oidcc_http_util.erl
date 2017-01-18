-module(oidcc_http_util).

-export([async_http/3, async_http/5]).
-export([sync_http/3, sync_http/5]).
-export([uncompress_body_if_needed/2]).


sync_http(Method, Url, Header) ->
    perform_request(Method, Url, Header, undefined, undefined,
                    [{body_format, binary}]).

sync_http(Method, Url, Header, ContentType, Body) ->
    perform_request(Method, Url, Header, ContentType, Body,
                    [{body_format, binary}]).

async_http(Method, Url, Header) ->
    perform_request(Method, Url, Header, undefined, undefined,
                    [{sync, false}]).


async_http(Method, Url, Header, ContentType, Body) ->
    perform_request(Method, Url, Header, ContentType, Body,
                    [{sync, false}]).




perform_request(Method, Url, Header, ContentType, Body, Options) ->
    case options(Url) of
        {ok, HttpOptions} ->
            Request = gen_request(Url, Header, ContentType, Body),
            Result = httpc:request(Method, Request, HttpOptions, Options),
            normalize_result(Result);
        Error ->
            Error
    end.

gen_request(Url, Header, undefined, undefined) ->
    {normalize(Url), normalize_headers(Header)};
gen_request(Url, Header, ContentType, Body) ->
    {normalize(Url), normalize_headers(Header), normalize(ContentType), Body}.


normalize_result({ok, {{_Proto, Status, _StatusName}, RespHeaders, Body}}) ->
    {ok, #{status => Status, header => RespHeaders, body => Body}};
normalize_result({ok, StreamId}) ->
    {ok, StreamId};
normalize_result({error, _} = Error) ->
     Error.



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

options(Url) when is_list(Url) ->
    {ok, {Schema, _, HostName, _, _,  _}} = http_uri:parse(normalize(Url)),
     case Schema of
        http -> {ok, []};
        https -> ssl_options(HostName)
    end;
options(Url) when is_binary(Url) ->
    options(binary_to_list(Url)).

ssl_options(HostName) ->
    VerifyFun = ssl_verify_fun(HostName),
    CaCert = application:get_env(oidcc, cacertfile),
    Depth = application:get_env(oidcc, cert_depth, 1),
    case CaCert of
        {ok, CaCertFile} ->
            {ok, [
                  {ssl, [
                         {verify, verify_peer},
                         {verify_fun, VerifyFun},
                         {cacertfile, CaCertFile},
                         {depth, Depth}
                        ] }
                 ]};
        _ ->
            {error, missing_cacertfile}
    end.


ssl_verify_fun(_Hostname) ->
    {
        fun (_, {bad_cert, _} = Reason, _) ->
                {fail, Reason};
            (_, {extension, _}, UserState) ->
                {unknown, UserState};
            (_, valid, UserState) ->
                {valid, UserState};
            (_Cert, valid_peer, UserState) ->
                %% TBSCert = Cert#'OTPCertificate'.tbsCertificate,
                %% Extensions = TBSCert#'OTPTBSCertificate'.extensions,
                %% case lists:keysearch(?'id-ce-subjectAltName',
                %%                      #'Extension'.extnID, Extensions) of
                %%     {value, #'Extension'{extnValue =
                %%                                [{dNSName, Hostname}]}} ->
                        %% {valid, UserState};
                %%     false ->
                %%         {fail, invalid_certificate_hostname}
                %% end
                {valid, UserState}
        end,
        []
    }.

normalize(L) when is_list(L) ->
    L;
normalize(B) when is_binary(B) ->
    binary_to_list(B).

normalize_headers(L) when is_list(L) ->
    [normalize_header(K, V) || {K, V} <- L].

normalize_header(K, V) ->
    {normalize(K), normalize(V)}.
