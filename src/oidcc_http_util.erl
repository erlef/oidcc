-module(oidcc_http_util).

-export([async_http/3, async_http/5]).
-export([sync_http/3, sync_http/5]).
-export([uncompress_body_if_needed/2]).


sync_http(Method, Url, Header) ->
    Result = httpc:request(Method,
                           {normalize(Url), normalize_headers(Header)},
                           options(Url),
                           [{body_format, binary}]),
    normalize_result(Result).

sync_http(Method, Url, Header, ContentType, InBody) ->
    Result = httpc:request(Method,
                           {normalize(Url), normalize_headers(Header),
                            normalize(ContentType), InBody
                           },
                           options(Url),
                           [{body_format, binary}]),
    normalize_result(Result).

async_http(Method, Url, Header) ->
    Result = httpc:request(Method,
                           {normalize(Url), normalize_headers(Header)},
                           options(Url),
                           [{sync, false}]),
    normalize_result(Result).


async_http(Method, Url, Header, ContentType, Body) ->
    Result = httpc:request(Method,
                           {normalize(Url), normalize_headers(Header),
                            normalize(ContentType), Body
                           },
                           options(Url),
                           [{sync, false}]),
    normalize_result(Result).


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

options(Url) ->
    {ok, {Schema, _, HostName, _, _,  _}} = http_uri:parse(normalize(Url)),
     case Schema of
        http -> [];
        https -> ssl_options(HostName)
    end.

ssl_options(HostName) ->
    VerifyFun = ssl_verify_fun(HostName),
    {ok, CaCertFile} = application:get_env(oidcc, cacertfile),
    [
      {ssl, [
             {verify, verify_peer},
             {verify_fun, VerifyFun},
             {cacertfile, CaCertFile}
            ] }
    ].


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

%% Private
normalize(L) when is_list(L) ->
    L;
normalize(B) when is_binary(B) ->
    binary_to_list(B).

normalize_headers(L) when is_list(L) ->
    [normalize_header(K, V) || {K, V} <- L].

normalize_header(K, V) ->
    {normalize(K), normalize(V)}.
