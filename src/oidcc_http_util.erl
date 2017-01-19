-module(oidcc_http_util).

-export([async_http/3, async_http/5]).
-export([sync_http/3, sync_http/5]).
-export([uncompress_body_if_needed/2]).
-export([qs/1, urlencode/1]).

-type qs_vals() :: [{binary(), binary() | true}].

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


%%% copied from cowlib, so there is no dependecy anymore
%% @doc Build an application/x-www-form-urlencoded string.

-spec qs(qs_vals()) -> binary().
qs([]) ->
    <<>>;
qs(L) ->
    qs(L, <<>>).

qs([], Acc) ->
    << $&, Qs/bits >> = Acc,
    Qs;
qs([{Name, true}|Tail], Acc) ->
    Acc2 = urlencode(Name, << Acc/bits, $& >>),
    qs(Tail, Acc2);
qs([{Name, Value}|Tail], Acc) ->
    Acc2 = urlencode(Name, << Acc/bits, $& >>),
    Acc3 = urlencode(Value, << Acc2/bits, $= >>),
    qs(Tail, Acc3).

-spec urlencode(B) -> B when B::binary().
urlencode(B) ->
    urlencode(B, <<>>).

urlencode(<< $\s, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $+ >>);
urlencode(<< $-, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $- >>);
urlencode(<< $., Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $. >>);
urlencode(<< $0, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $0 >>);
urlencode(<< $1, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $1 >>);
urlencode(<< $2, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $2 >>);
urlencode(<< $3, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $3 >>);
urlencode(<< $4, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $4 >>);
urlencode(<< $5, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $5 >>);
urlencode(<< $6, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $6 >>);
urlencode(<< $7, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $7 >>);
urlencode(<< $8, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $8 >>);
urlencode(<< $9, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $9 >>);
urlencode(<< $A, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $A >>);
urlencode(<< $B, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $B >>);
urlencode(<< $C, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $C >>);
urlencode(<< $D, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $D >>);
urlencode(<< $E, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $E >>);
urlencode(<< $F, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $F >>);
urlencode(<< $G, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $G >>);
urlencode(<< $H, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $H >>);
urlencode(<< $I, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $I >>);
urlencode(<< $J, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $J >>);
urlencode(<< $K, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $K >>);
urlencode(<< $L, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $L >>);
urlencode(<< $M, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $M >>);
urlencode(<< $N, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $N >>);
urlencode(<< $O, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $O >>);
urlencode(<< $P, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $P >>);
urlencode(<< $Q, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $Q >>);
urlencode(<< $R, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $R >>);
urlencode(<< $S, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $S >>);
urlencode(<< $T, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $T >>);
urlencode(<< $U, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $U >>);
urlencode(<< $V, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $V >>);
urlencode(<< $W, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $W >>);
urlencode(<< $X, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $X >>);
urlencode(<< $Y, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $Y >>);
urlencode(<< $Z, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $Z >>);
urlencode(<< $_, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $_ >>);
urlencode(<< $a, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $a >>);
urlencode(<< $b, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $b >>);
urlencode(<< $c, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $c >>);
urlencode(<< $d, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $d >>);
urlencode(<< $e, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $e >>);
urlencode(<< $f, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $f >>);
urlencode(<< $g, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $g >>);
urlencode(<< $h, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $h >>);
urlencode(<< $i, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $i >>);
urlencode(<< $j, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $j >>);
urlencode(<< $k, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $k >>);
urlencode(<< $l, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $l >>);
urlencode(<< $m, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $m >>);
urlencode(<< $n, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $n >>);
urlencode(<< $o, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $o >>);
urlencode(<< $p, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $p >>);
urlencode(<< $q, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $q >>);
urlencode(<< $r, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $r >>);
urlencode(<< $s, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $s >>);
urlencode(<< $t, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $t >>);
urlencode(<< $u, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $u >>);
urlencode(<< $v, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $v >>);
urlencode(<< $w, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $w >>);
urlencode(<< $x, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $x >>);
urlencode(<< $y, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $y >>);
urlencode(<< $z, Rest/bits >>, Acc) -> urlencode(Rest, << Acc/bits, $z >>);
urlencode(<< C, Rest/bits >>, Acc) ->
    H = hex(C bsr 4),
    L = hex(C band 16#0f),
    urlencode(Rest, << Acc/bits, $%, H, L >>);
urlencode(<<>>, Acc) ->
    Acc.

hex( 0) -> $0;
hex( 1) -> $1;
hex( 2) -> $2;
hex( 3) -> $3;
hex( 4) -> $4;
hex( 5) -> $5;
hex( 6) -> $6;
hex( 7) -> $7;
hex( 8) -> $8;
hex( 9) -> $9;
hex(10) -> $A;
hex(11) -> $B;
hex(12) -> $C;
hex(13) -> $D;
hex(14) -> $E;
hex(15) -> $F.
