%% -*- erlang-indent-level: 4; indent-tabs-mode: nil; fill-column: 80 -*-
%%% Copyright Erlware, LLC. All Rights Reserved.
%%%
%%% This file is provided to you under the Apache License,
%%% Version 2.0 (the "License"); you may not use this file
%%% except in compliance with the License.  You may obtain
%%% a copy of the License at
%%%
%%%   http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing,
%%% software distributed under the License is distributed on an
%%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%%% KIND, either express or implied.  See the License for the
%%% specific language governing permissions and limitations
%%% under the License.
%%%-------------------------------------------------------------------
%%% @author Scott Parish <srp@srparish.net>
%%% @copyright Erlware, LLC.
%%% @doc A module for generating, parsing, encoding, and decoding uris.
%%%
%%% At the moment this module isn't very sympathetic to non-http
%%% uri's, but that could/should change in the future.
-module(uri).

-compile(export_all).

-export([new/7, from_string/1, from_http_1_1/3, to_string/1,
         query_foldl/3,
         query_to_proplist/1,
         to_query/1, to_query/2,
         quote/1, quote/2,
         unquote/1,
         scheme/1, scheme/2, user_info/1, user_info/2, host/1, host/2,
         port/1, port/2, path/1, path/2, append_path/2,
         raw_query/1, raw_query/2,
         q/1, q/2,
         frag/1, frag/2, raw/1]).

-include_lib("eunit/include/eunit.hrl").

-record(uri, {scheme ::  binary(),       % <<"http">>, <<"ftp">>
              user_info="" :: binary(), % <<>> | <<"srp">>
              host="" :: binary(),      % <<"somewhere.net">>
              port=undefined :: integer() | undefined,      % undefined | 80 | 8080
              path="" :: binary(),      % <<"/here/there/everytwhere">>
              q=[] :: proplists:proplist(),  % The q as a dict
              frag="" :: binary(),      % <<"some anchor">>
              raw= <<"">>  :: binary()          % original raw uri
             }).

%%============================================================================
%% types
%%============================================================================

-export_type([t/0]).

-opaque t() :: #uri{}.
%%  This is a record that represents the different parts of a uri,
%%  as defined by rfc-2396. It has the following fields:
%%  <dl>
%%   <dt>scheme::binary()</dt>
%%   <dd>`"http"', `"https"', `"ftp"', etc</dd>
%%
%%   <dt>user_info::binary()</dt>
%%   <dd>This will be `"parish:secret"' for the uri
%%       `"http://parish:secret@somehost.com/index.html"'</dd>
%%
%%   <dt>host::binary()</dt>
%%   <dd>This will be `"somehost.com"' for the uri
%%       `"http://somehost.com/index.html"'.</dd>
%%
%%   <dt>port::integer() | undefined</dt>
%%   <dd>This will be `8080' for the uri
%%       `"http://somehost.com:8080/index.html"', and `[]' for
%%       uri `"http://somehost.com/index.html"'.</dd>
%%
%%   <dt>path::binary()</dt>
%%   <dd>This will be `"/index.html"' for the uri
%%       `"http://somehost.com/index.html?startId=50"'. This will
%%       be unquoted, so `"http://somehost.com/name+with%20spaces"'
%%       will be `"/name with spaces"'</dd>
%%
%%   <dt>q::dict()</dt>
%%   <dd> This is a dict of name value pairs from the query. If no query
%%        was found then it is left empty </dd>
%%
%%   <dt>frag::binary()</dt>
%%   <dd>The fragment part of the url, unquoted. This will be
%%       `"Section 5"' for the uri
%%       `"http://somehost.com/index.html#Section+5"'. It will be
%%       The empty string if no fragment is found.</dd>
%%
%%   <dt>raw::binary()</dt>
%%   <dd>This is the original uri that the above fields were populated
%%       from. Everything will still be in their original quoted form.
%%       Note that this may be a best guess as to the uri a user had
%%       in their browser, as this will most likely be formed by
%%       concatenating the `Host' header with the `request' line uri.</dd>
%%  </dl>
%%

%%============================================================================
%% API
%%============================================================================

%% @doc Populate a new uri record by parsing the string `Uri'
-spec from_string(string() | binary()) -> t().
from_string(Uri)
  when erlang:is_list(Uri) ->
    from_string(erlang:iolist_to_binary(Uri));
from_string(Uri)
  when erlang:is_binary(Uri) ->
    {Scheme, Uri1} = parse_scheme(Uri),

    {Authority, Uri2} = parse_authority(Uri1),
    {UserInfo, HostPort} = parse_user_info(Authority),
    {Host, Port} = parse_host_port(HostPort),

    {Path, Uri3} = parse_path(Uri2),
    {Query, Uri4} = parse_query(Uri3),
    Frag = parse_frag(Uri4),
    new(Scheme, UserInfo, Host, Port, Path, Query, Frag).

%% @doc Return the string this uri represents. (Same as the `raw'
%% field)
-spec to_string(t()) -> binary().
to_string(#uri{raw = Raw}) ->
    Raw.

%% @doc Populate a new #uri record by using `Scheme' and parsing
%% `HostPort' string `Uri'
-spec from_http_1_1(binary(), binary(), binary()) -> t().
from_http_1_1(Scheme, HostPort, Uri) ->
    {Host, Port} = parse_host_port(HostPort),
    {Path, Uri1} = parse_path(Uri),
    {Query, Uri2} = parse_query(Uri1),
    Frag = parse_frag(Uri2),
    new(Scheme, <<"">>, Host, Port, Path, Query, Frag).

%% @doc Return a uri record with the given fields. Use `""' for any field
%% that isn't used.
%%
%% You probably want {@link raw/7} unless you've parsed a uri yourself.
-spec new(binary(), binary(), binary(), integer() | undefined, binary(),
          proplists:proplist() | binary(), binary()) ->
                 t().
new(Scheme, UserInfo, Host, Port, Path, Query, Frag)
  when erlang:is_binary(Query) ->
    new(Scheme, UserInfo, Host, Port, Path, query_to_proplist(Query), Frag);
new(Scheme, UserInfo, Host, Port, Path, Query, Frag)
when erlang:is_list(Query) ->
    update_raw(#uri{scheme = Scheme,
                    user_info = unquote(UserInfo),
                    host = Host,
                    port = Port,
                    path = unquote(Path),
                    q = Query,
                    frag = unquote(Frag)}).

%% @doc Convert the string or the `raw_query' portion of {@link t()} into a
%%      {@link proplists:proplist()}, where the keys are binaries, the values
%%      are binaries, and for valueless keys, the atom `true' is used as the
%%      value.
%%
%%      For example, `"range=5-50&printable"' would result in the following
%%      proplist entries:
%%      <table>
%%       <tr><th>Key</th><th>Value</th></tr>
%%       <tr><td>"range"</td><td>"5-50"</td></tr>
%%       <tr><td>"printable"</td><td>true</td></tr>
%%      </table>
%%
%%      The string needent have to be from a uri, this method is also
%%      useful for decoding the `Post' body of an HTTP form submission.
-spec query_to_proplist(binary()) -> proplists:proplist().
query_to_proplist(Query) ->
    lists:reverse(query_foldl(fun (KV, Acc) -> [KV | Acc] end, [], Query)).


%% @doc Fold over each element of a query. For instance with the
%%      query `"range=5-50&printable"', `F' will be called as
%%      `F("range", "5-50", Acc)' and `F("printable", true, Acc)'.
%%      Both `Key' and `Value' are already unquoted when `F' is called.
%% @see query_to_dict/1
-spec query_foldl(fun((proplists:property(), Acc::term()) -> term()),
                  Acc, proplists:proplist() | binary() | t()) -> Acc.
query_foldl(F, Init, #uri{q = Query}) ->
    query_foldl(F, Init, Query);
query_foldl(F, Init, Query)
  when erlang:is_binary(Query) ->
    lists:foldl(fun (Part, Acc) ->
                        case binary:split(Part, <<"=">>) of
                            [Key, Value] ->
                                F({unquote(Key), unquote(Value)}, Acc);
                            [<<>>] ->
                                Acc;
                            [Key] ->
                                F({unquote(Key), true}, Acc)
                        end
                end, Init, binary:split(erlang:iolist_to_binary(Query), <<"&">>));
query_foldl(F, Init, Query)
  when erlang:is_list(Query) ->
    lists:foldl(F, Init, Query).


%% @doc Convert a dictionary or proplist to an iolist representing the
%% query part of a uri. Keys and values can be binaries, lists, atoms,
%% integers or floats, and will be automatically converted to a string and
%% quoted.
to_query(List)
  when erlang:is_list(List) ->
    to_query(fun lists:foldl/3, List).

%% @doc Return an binary representing the query part of a uri by
%% folding over `Ds' by calling the provided `FoldF', which should
%% take three arguments: a function, an initial accumulator value, and
%% the datastructure to fold over.
%% @see to_query/1
-spec to_query(function(), binary() | proplist:proplist()) -> binary().
to_query(FoldF, Ds) ->
    FoldF(fun ({K, V}, <<>>) ->
                  KB = quote(el_to_string(K), q),
                  VB = quote(el_to_string(V), q),
                  <<KB/binary, <<"=">>/binary,
                    VB/binary>>;
              ({K, V}, Acc) ->
                  KB = quote(el_to_string(K), q),
                  VB = quote(el_to_string(V), q),
                  <<Acc/binary, $&, KB/binary, <<"=">>/binary,
                    VB/binary>>;
              (K, <<>>) ->
                  KB = quote(el_to_string(K), q),
                  KB;
              (K, Acc) ->
                  KB = quote(el_to_string(K), q),
                  <<Acc/binary, $&, KB/binary>>
              end, <<>>, Ds).

%% @doc Return `Str' with all `+' replaced with space, and `%NN' replaced
%%      with the decoded byte.
-spec unquote(binary()) -> binary().
unquote(Str) ->
    unquote(Str, <<>>).

%% @doc Return `Str' with all reserved or uri-unsafe characters in
%%      quoted form. For instance `"A Space"' becomes `"A%20Space"'.
%%      This is the same as calling `quote(Str, any)'.
%% @see quote/2
-spec quote(binary()) -> binary().
quote(Str) ->
    quote(Str, any).

%% @doc Return `Str' with all reserved or uri-unsafe characters in
%%      quoted form. Since rfc-2396 has different reserved characters
%%      for different parts of the uri, you can specify `Part' to
%%      obtain a minimally quoted uri for that `Part'.
%%
%%      `Part' can be one of the following values:
%%      <dl>
%%       <dt>any</dt>
%%       <dd>Quote any character that is reserved in any potential part.</dd>
%%
%%       <dt>userinfo</dt>
%%       <dd>Quote for the userinfo part of a uri.</dd>
%%
%%       <dt>path</dt>
%%       <dd>Quote for the path part of a uri.</dd>
%%
%%       <dt>segment</dt>
%%       <dd>Quote for a path's segment. This is much like `path', but
%%           will also quote the `/' character.</dd>
%%
%%       <dt>segment_param</dt>
%%       <dd>Quote for path segment's parameters (a fairly obscure part
%%           of uris). This is like `path' but will also quote the characters
%%           `/' and `;'.</dd>
%%
%%       <dt>query_ | q</dt>
%%       <dd>Quote for query parts. `query' is an erlang keyword so you can
%%           either use `` q '' or `query_' to specify this part. This
%%           will quote characters such as `&' and `=', so it needs to be
%%           called on the individual key/value parts of a query. See
%%           {@link to_query/1} and {@link to_query/1}.</dd>
%%
%%       <dt>frag</dt>
%%       <dd>Quote for the fragment part of a uri</dd>
%%      </dl>
-spec quote(binary(), atom()) -> binary().
quote(Str, Part) ->
    binary_foldl(fun (C, Acc) ->
                         Escaped = escape_for_part(C, Part),
                         <<Acc/binary, Escaped/binary>>
                 end, <<>>, Str).

%% @doc Return the scheme field of {@link t()}.
-spec scheme(t()) -> binary().
scheme(#uri{scheme = Scheme}) ->
    Scheme.

%% @doc Set the scheme field of {@link t()}.
-spec scheme(t(), binary()) -> t().
scheme(Uri, NewScheme) ->
    update_raw(Uri#uri{scheme = NewScheme}).

%% @doc Return the user_info field of {@link t()}.
-spec user_info(t()) -> binary().
user_info(#uri{user_info = UserInfo}) ->
    UserInfo.

%% @doc Set the user_info field of {@link t()}.
-spec user_info(t(), binary()) -> t().
user_info(Uri, NewUserInfo) ->
    update_raw(Uri#uri{user_info = NewUserInfo}).

%% @doc Return the host field of {@link t()}.
-spec host(t()) -> binary().
host(#uri{host = Host}) ->
    Host.

%% @doc Set the host field of {@link t()}.
-spec host(t(), binary()) -> t().
host(Uri, NewHost) ->
    update_raw(Uri#uri{host = NewHost}).

%% @doc Return the port field of {@link t()}.
-spec port(t()) -> integer().
port(#uri{port = Port}) ->
    Port.

%% @doc Set the port field of {@link t()}.
-spec port(t(), integer()) -> t().
port(Uri, NewPort) ->
    update_raw(Uri#uri{port = NewPort}).

%% @doc Return the path field of {@link t()}.
-spec path(t()) -> binary().
path(#uri{path = Path}) ->
    Path.

%% @doc Set the path field of {@link t()}.
-spec path(t(), binary()) -> t().
path(Uri, NewPath) ->
    update_raw(Uri#uri{path = NewPath}).
%% @doc Append a path to the existing path of the system
-spec append_path(t(), binary()) -> t().
append_path(Uri=#uri{path=Path}, NewPath) ->
    path(Uri, <<Path/binary, <<"/">>/binary, NewPath/binary>>).

%% @doc Return the raw_query field of {@link t()}.
-spec raw_query(t()) -> binary().
raw_query(#uri{q = Query}) ->
    to_query(Query).

%% @doc Set the raw_query field of {@link t()}.
-spec raw_query(t(), binary()) -> t().
raw_query(Uri, NewRawQuery) ->
    update_raw(Uri#uri{q = query_to_proplist(NewRawQuery)}).

%% @doc Return the query field of {@link t()}.
-spec q(t()) -> proplists:proplist().
q(#uri{q = Query}) ->
    Query.

%% @doc Set the query field of {@link t()}.
-spec q(t(), proplists:proplist()) -> t().
q(Uri, Query)
  when erlang:is_list(Query) ->
    update_raw(Uri#uri{q = Query}).

%% @doc Return the frag field of {@link t()}.
-spec frag(t()) -> binary().
frag(#uri{frag = Frag}) ->
    Frag.

%% @doc Set the frag field of {@link t()}.
-spec frag(t(), binary()) -> t().
frag(Uri, NewFrag) ->
    update_raw(Uri#uri{frag = NewFrag}).

%% @doc Return the raw field of {@link t()}.
-spec raw(t()) -> binary().
raw(#uri{raw = Raw}) ->
    Raw.

%%============================================================================
%% Internal Functions
%%============================================================================

parse_scheme(Uri) ->
    parse_scheme(Uri, <<>>).

parse_scheme(<<$:, Uri/binary>>, Acc) ->
    {Acc, Uri};
parse_scheme(<<>>, Acc) ->
    {<<>>, Acc};
parse_scheme(<<C, Rest/binary>>, Acc) ->
    parse_scheme(Rest, <<Acc/binary, C>>).

parse_authority(<<$/, $/, Uri/binary>>) ->
    parse_authority(Uri, <<"">>);
parse_authority(Uri) ->
    Uri.

parse_authority(<<$/, Rest/binary>>, Acc) ->
    {Acc, <<$/, Rest/binary>>};
parse_authority(<<>>, Acc) ->
    {Acc, <<>>};
parse_authority(<<C,  Rest/binary>>, Acc) ->
    parse_authority(Rest, <<Acc/binary, C>>).

parse_user_info(Authority) ->
    parse_user_info(Authority, <<>>).

parse_user_info(<<$@, HostPort/binary>>, Acc) ->
    {Acc, HostPort};
parse_user_info(<<>>, Acc) ->
    {<<>>, Acc};
parse_user_info(<<C, HostPort/binary>>, Acc) ->
    parse_user_info(HostPort, <<Acc/binary, C>>).

parse_host_port(HostPort) ->
    case binary:split(HostPort, <<":">>) of
        [Host] ->
            {Host, undefined};
        [Host, <<>>] ->
            {Host, undefined};
        [Host, Port] ->
            {Host, erlang:list_to_integer(erlang:binary_to_list(Port))};
        _ ->
            erlang:throw({uri_error, {invalid_host_port, HostPort}})
    end.

parse_path(Uri) ->
    parse_path(Uri, <<>>).

parse_path(<<C, Uri/binary>>, Acc)
  when C == $?; C == $# ->
    {Acc, <<C, Uri/binary>>};
parse_path(<<>>, Acc) ->
    {Acc, <<"">>};
parse_path(<<C, Uri/binary>>, Acc) ->
    parse_path(Uri, <<Acc/binary, C>>).

parse_query(<<$?, Uri/binary>>) ->
    parse_query(Uri, <<>>);
parse_query(Uri) ->
    {<<>>, Uri}.

parse_query(<<$#, Uri/binary>>, Acc) ->
    {Acc, <<$#, Uri/binary>>};
parse_query(<<>>, Acc) ->
    {Acc, <<"">>};
parse_query(<<C, Rest/binary>>, Acc) ->
    parse_query(Rest, <<Acc/binary, C>>).

parse_frag(<<$#, Frag/binary>>) ->
    unquote(Frag);
parse_frag(<<>>) ->
    <<>>;
parse_frag(Data) ->
    erlang:throw({uri_error, {data_left_after_parsing, Data}}).

user_info_to_string(#uri{user_info = <<>>}) ->
    <<>>;
user_info_to_string(#uri{user_info = UserInfo}) ->
    <<UserInfo/binary, $@>>.

port_to_string(#uri{port = undefined}) ->
    <<>>;
port_to_string(#uri{port = Port}) ->
    BPort = erlang:list_to_binary(erlang:integer_to_list(Port)),
    <<$:, BPort/binary>>.

path_to_string(#uri{path = <<>>}) ->
    $/;
path_to_string(#uri{path = Path}) ->
    case quote(Path, path) of
        <<$/, _/binary>> ->
            Path;
        QuotedPath ->
            <<$/, QuotedPath/binary>>
    end.

query_to_string(#uri{q = []}) ->
    <<"">>;
query_to_string(#uri{q = Query}) ->
    RawQuery = to_query(Query),
    <<$?, RawQuery/binary>>.

frag_to_string(#uri{frag = <<>>}) ->
    <<>>;
frag_to_string(#uri{frag = Frag}) ->
    BQuote = quote(Frag, frag),
    <<$#, BQuote/binary>>.

el_to_string(El)
  when erlang:is_atom(El) ->
    erlang:iolist_to_binary(erlang:atom_to_list(El));
el_to_string(El)
  when erlang:is_integer(El) ->
    erlang:iolist_to_binary(erlang:integer_to_list(El));
el_to_string(El)
  when erlang:is_float(El) ->
    erlang:iolist_to_binary(erlang:float_to_list(El));
el_to_string(El)
  when erlang:is_list(El) ->
    erlang:list_to_binary(El);
el_to_string(El)
  when erlang:is_binary(El) ->
    El.

unquote(<<>>, Acc) ->
    Acc;
unquote(<<$+, Str/binary>>, Acc) ->
    unquote(Str, <<Acc/binary, $\s>>);
unquote(<<$\%, A, B, Str/binary>>, Acc) ->
    Char = erlang:list_to_integer([A, B], 16),
    unquote(Str, <<Acc/binary, Char>>);
unquote(<<C, Str/binary>>, Acc) ->
    unquote(Str, <<Acc/binary, C/integer>>).

escape_for_part(C, Part) ->
    IsReserved = case Part of
                     any ->
                         is_unreserved(C);
                     userinfo ->
                         is_userinfo(C);
                     path ->
                         is_pchar(C) orelse C == $; orelse C == $/;
                     segment ->
                         is_pchar(C) orelse C == $;;
                     segment_param ->
                         is_pchar(C);
                     query_ ->
                         is_unreserved(C);
                     q ->
                         is_unreserved(C);
                     fragment ->
                         is_unreserved(C);
                     frag ->
                         is_unreserved(C)
                 end,
    case IsReserved of
        true ->
            <<C>>;
        false ->
            escape(C)
    end.

escape(C) ->
    erlang:iolist_to_binary(io_lib:format("%~2.16.0B", [C])).

is_unreserved(C) ->
    is_alphanum(C) orelse is_mark(C).
is_alphanum(C) ->
    is_alpha(C) orelse is_digit(C).
is_alpha(C) ->
    is_lowalpha(C) orelse is_upalpha(C).
is_lowalpha(C) ->
    $a =< C andalso C =< $z.
is_upalpha(C) ->
    $A =< C andalso C =< $Z.
is_digit(C) ->
    $0 =< C andalso C =< $9.

is_pchar($:) ->
    true;
is_pchar($@) ->
    true;
is_pchar($&) ->
    true;
is_pchar($=) ->
    true;
is_pchar($+) ->
    true;
is_pchar($$) ->
    true;
is_pchar($,) ->
    true;
is_pchar(C)  ->
    is_unreserved(C).

is_userinfo($;) ->
    true;
is_userinfo($:) ->
    true;
is_userinfo($&) ->
    true;
is_userinfo($=) ->
    true;
is_userinfo($+) ->
    true;
is_userinfo($$) ->
    true;
is_userinfo($,) ->
    true;
is_userinfo(C)  ->
    is_unreserved(C).

is_mark($-) ->
    true;
is_mark($_) ->
    true;
is_mark($.) ->
    true;
is_mark($!) ->
    true;
is_mark($~) ->
    true;
is_mark($*) ->
    true;
is_mark($\') ->
    true;
is_mark($() ->
    true;
is_mark($)) ->
    true;
is_mark(_) ->
    false.

update_raw(Uri) ->
    Uri#uri{raw = erlang:iolist_to_binary(to_iolist(Uri))}.

to_iolist(Uri) ->
    [Uri#uri.scheme, <<"://">>, user_info_to_string(Uri), Uri#uri.host,
     port_to_string(Uri), path_to_string(Uri), query_to_string(Uri),
     frag_to_string(Uri)].

binary_foldl(_Fun, Acc0, <<>>) ->
    Acc0;
binary_foldl(Fun, Acc0, <<H, T/binary>>) ->
    Acc1 = Fun(H, Acc0),
    binary_foldl(Fun, Acc1, T).


%%%===================================================================
%%% Test Functions
%%%===================================================================

-ifndef(NOTEST).
-include_lib("eunit/include/eunit.hrl").

new_test() ->
    ?assertMatch(<<"http://myhost.com:8080/my/path?color=red#Section%205">>,
                 to_string(new(<<"http">>, <<>>, <<"myhost.com">>, 8080, <<"my/path">>,
                               <<"color=red">>, <<"Section 5">>))).

append_path_test() ->
    T0 = new(<<"http">>, <<"">>, <<"myhost.com">>, 8080,
             <<"/my/path">>, <<"color=red">>, <<"Section 5">>),
    T1 = append_path(T0, <<"additional/path">>),
    ?assertMatch(<<"http://myhost.com:8080/my/path/additional/path?color=red#Section%205">>,
                 to_string(T1)).

parse_scheme_test() ->
    ?assertMatch({<<"http">>, <<"//test.com/">>}, parse_scheme(<<"http://test.com/">>)),
    ?assertMatch({<<>>, <<"/test">>}, parse_scheme(<<"/test">>)),
    ?assertMatch({<<"mailto">>, <<"x@test.com">>}, parse_scheme(<<"mailto:x@test.com">>)).

parse_authority_test() ->
    ?assertMatch({<<"test.com">>, <<"/here">>}, parse_authority(<<"//test.com/here">>)),
    ?assertMatch({<<"test.com">>, <<"">>}, parse_authority(<<"//test.com">>)),
    ?assertMatch(<<"/test">>, parse_authority(<<"/test">>)).

parse_user_info_test() ->
    ?assertMatch({<<"user">>, <<"test.com">>}, parse_user_info(<<"user@test.com">>)),
    ?assertMatch({<<"">>, <<"user.test.com">>}, parse_user_info(<<"user.test.com">>)).

parse_host_port_test() ->
    ?assertMatch({<<"test.com">>, 8080}, parse_host_port(<<"test.com:8080">>)),
    ?assertMatch({<<"test.com">>, undefined}, parse_host_port(<<"test.com">>)).

parse_path_test() ->
    ?assertMatch({<<"/a/b/c">>, <<"">>}, parse_path(<<"/a/b/c">>)),
    ?assertMatch({<<"/a/b/c">>, <<"?n=5">>}, parse_path(<<"/a/b/c?n=5">>)),
    ?assertMatch({<<"/a/b/c">>, <<"#anchor">>}, parse_path(<<"/a/b/c#anchor">>)),
    ?assertMatch({<<"">>, <<"">>}, parse_path(<<"">>)).

parse_query_test() ->
    ?assertMatch({<<"a=b">>, <<"">>}, parse_query(<<"?a=b">>)),
    ?assertMatch({<<"a=b">>, <<"#anchor">>}, parse_query(<<"?a=b#anchor">>)),
    ?assertMatch({<<"">>, <<"#anchor">>}, parse_query(<<"#anchor">>)),
    ?assertMatch({<<"">>, <<"">>}, parse_query(<<"">>)).

query_to_proplist_test() ->
    ?assertMatch([], query_to_proplist(<<>>)),
    ?assertMatch([{<<"a">>, <<"b">>}], query_to_proplist(<<"a=b&">>)),
    ?assertMatch([{<<"a">>, <<>>}], query_to_proplist(<<"a=">>)),
    ?assertMatch([{<<"a">>, true}, {<<"b">>, <<"c">>}], query_to_proplist(<<"a&b=c">>)),
    ?assertMatch([{<<"a&b">>, <<"!t=f">>}], query_to_proplist(<<"a%26b=!t%3Df">>)).

to_query_test() ->
    ?assertMatch(
       <<"one&two=2&three=two%20%2B%20one">>,
       to_query([one, {<<"two">>, 2}, {<<"three">>, <<"two + one">>}])).

proplist_query_test() ->
    QueryPropList = [{<<"foo">>, <<"bar">>}, {<<"baz">>, <<"back">>}],
    Uri0 = from_string(<<"http://myhost.com:8080/my/path?color=red#Section%205">>),
    Uri1 = q(Uri0, QueryPropList),
    ?assertMatch(<<"http://myhost.com:8080/my/path?foo=bar&baz=back#Section%205">>,
                     to_string(Uri1)).


unquote_test() ->
    ?assertMatch(<<"ab">>, unquote(<<"ab">>)),
    ?assertMatch(<<"a b">>, unquote(<<"a+b">>)),
    ?assertMatch(<<"a b">>, unquote(<<"a%20b">>)).

quote_test() ->
    ?assertMatch(<<"abc123">>, quote(<<"abc123">>)),
    ?assertMatch(<<"abc%20123">>, quote(<<"abc 123">>)).

escape_test() ->
    ?assertMatch(<<"%20">>, escape($\s)).

-endif.
