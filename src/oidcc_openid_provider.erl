-module(oidcc_openid_provider).
-behaviour(gen_server).

%% API.
-export([start_link/1]).
-export([set_name/2]).
-export([set_description/2]).
-export([set_client_id/2]).
-export([set_client_secret/2]).
-export([set_config_endpoint/2]).
-export([update_config/1]).
-export([set_local_endpoint/2]).
-export([get_config/1]).

%% gen_server.
-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).
-export([terminate/2]).
-export([code_change/3]).

-record(state, {
          id = undefined,
          name = undefined,
          desc = none,
          client_id = unknown,
          client_secret = unknown,
          config_ep = unknown,
          config = #{},
          ready = false,
          lasttime_updated = never,
          local_endpoint = unknown,

          client_pid = none,
          retrieving = none
}).

%% API.

-spec start_link(Id :: binary()) -> {ok, pid()}.
start_link(Id) ->
	gen_server:start_link(?MODULE, Id, []).

-spec set_name(Name :: binary(), Pid :: pid() ) -> ok.
set_name(Name, Pid) ->
    gen_server:call(Pid,{set_name,Name}).

-spec set_description(Description :: binary(), Pid :: pid() ) -> ok.
set_description(Description, Pid) ->
    gen_server:call(Pid,{set_description,Description}).

-spec set_client_id(ClientId :: binary(), Pid :: pid() ) -> ok.
set_client_id(ClientId, Pid) ->
    gen_server:call(Pid,{set_client_id,ClientId}).

-spec set_client_secret(ClientSecret :: binary(), Pid :: pid() ) -> ok.
set_client_secret(ClientSecret, Pid) ->
    gen_server:call(Pid,{set_client_secret,ClientSecret}).


-spec set_config_endpoint(ConfigEndpoint :: binary(), Pid :: pid() ) -> ok.
set_config_endpoint(ConfigEndpoint, Pid) ->
    gen_server:call(Pid,{set_config_endpoint,ConfigEndpoint}).

-spec update_config(Pid :: pid() ) -> ok.
update_config(Pid) ->
    gen_server:call(Pid,update_config).

-spec set_local_endpoint(Url :: binary(), Pid :: pid() ) -> ok.
set_local_endpoint(Url, Pid) ->
    gen_server:call(Pid,{set_local_endpoint,Url}).

-spec get_config( Pid :: pid() ) -> {ok, Config :: map()}.
get_config( Pid) ->
    gen_server:call(Pid,get_config).
%% gen_server.

init(Id) ->
	{ok, #state{id = Id}}.

handle_call(get_config, _From, State) ->
    Conf = create_config(State), 
	{reply, {ok, Conf}, State};
handle_call({set_name,Name}, _From, State) ->
	{reply, ok, State#state{name = Name}};
handle_call({set_description,Description}, _From, State) ->
	{reply, ok, State#state{desc = Description}};
handle_call({set_client_id,ClientId}, _From, State) ->
	{reply, ok, State#state{client_id=ClientId}};
handle_call({set_client_secret,ClientSecret}, _From, State) ->
	{reply, ok, State#state{client_secret=ClientSecret}};
handle_call({set_local_endpoint,Url}, _From, State) ->
	{reply, ok, State#state{local_endpoint=Url}};
handle_call({set_config_endpoint,ConfigEndpoint}, _From, State) ->
    ok = trigger_config_retrieval(),
	{reply, ok, State#state{config_ep=ConfigEndpoint}};
handle_call(update_config, _From, State) ->
    ok = trigger_config_retrieval(),
	{reply, ok, State};
handle_call(_Request, _From, State) ->
	{reply, ignored, State}.


handle_cast(retrieve_config, State) ->
    {ok, ConPid} = retrieve_config(State),
 	{noreply, State#state{client_pid = ConPid,retrieving=config}};
handle_cast(retrieve_keys, State) ->
    {ok, ConPid} = retrieve_keys(State),
 	{noreply, State#state{client_pid = ConPid, retrieving=keys}};
handle_cast(_Msg, State) ->
	{noreply, State}.

handle_info({http_client_result, HttpMap}, State) ->
    State2 = handle_http_result(HttpMap, State),
	{noreply, State2};
handle_info({http_client_crashed, Reason}, State) ->
    State2 = handle_http_client_crash(State, Reason), 
	{noreply, State2};
handle_info(_Info, State) ->
	{noreply, State}.

terminate(_Reason, _State) ->
	ok.

code_change(_OldVsn, State, _Extra) ->
	{ok, State}.

retrieve_config(#state{client_pid = ConPid, config_ep = ConfigEndpoint}) ->
    stop_existing_client(ConPid),
    ehtc:http_get(ConfigEndpoint). 

retrieve_keys(#state{client_pid = ConPid, config = Config}) ->
    KeyEndpoint = maps:get(jwks_uri,Config,undefined),
    Header = [{<<"accept">>,"application/json"}],
    stop_existing_client(ConPid),
    ehtc:http_get(KeyEndpoint, Header). 

handle_http_result(200, Header,Body, config,  State) ->
    handle_config(Body, Header, State);
handle_http_result(200, Header,Body, keys,  State) ->
    handle_keys(Body, Header, State);
handle_http_result(_Status, _Header, _Body, _Retrieve,  State) ->
    State.


handle_http_result(HttpData, #state{ retrieving = Retrieve} = State) ->
    #{header := Header, status := Status, body := Body} = HttpData,
    State2 = State#state{client_pid=none,retrieving=none},
    handle_http_result(Status, Header, Body, Retrieve, State2).



stop_existing_client(none) ->
    ok;
stop_existing_client(Pid) ->
    ehtc:tclose(Pid).

create_config(#state{id = Id, desc = Desc,  client_id = ClientId,  client_secret =
                     ClientSecret, config_ep = ConfEp, config=Config,
                     lasttime_updated = LastTimeUpdated, ready = Ready,
                     local_endpoint = LocalEndpoint}) ->
    StateList = [{id,Id}, {description,Desc}, {client_id, ClientId},
                 {client_secret, ClientSecret}, {config_endpoint, ConfEp},
                 {lasttime_updated, LastTimeUpdated}, {ready, Ready}, 
                 {local_endpoint, LocalEndpoint}],
    maps:merge(Config, maps:from_list(StateList)).




    
handle_config(Data, _Header, State) ->
    %TODO: implement update at expire data/time
    Config = jsx:decode(Data,[return_maps, {labels, attempt_atom}]),
    ok = trigger_key_retrieval(),
    timer:apply_after(3600000,?MODULE,update_config,[self()]),
    State#state{config = Config}. 

handle_keys(Data, _Header, #state{config = Config } = State) ->
    %TODO: implement update at expire data/time
    #{keys := KeyList } = jsx:decode(Data,[return_maps, {labels, attempt_atom}]),
    Keys = extract_supported_keys(KeyList,[]),
    State#state{config = maps:put(keys, Keys, Config), ready = true,
                lasttime_updated = timestamp()}. 

extract_supported_keys([], List) ->
    List;
extract_supported_keys([#{ kty := <<"RSA">>, 
                           alg := <<"RS256">>, 
                           use := <<"sig">>,
                           n := N0,
                           e := E0
                         } = Map|T], List) ->
    Kid = maps:get(kid,Map,unknown),
    N = binary:decode_unsigned(base64url:decode(N0)),
    E = binary:decode_unsigned(base64url:decode(E0)),
    Key = #{kty => rsa, alg => rs256, use => sign, key => [E,N], kid => Kid }, 
    extract_supported_keys(T, [Key | List]);
extract_supported_keys([_H|T], List) ->
    extract_supported_keys(T, List).
   


handle_http_client_crash(_State, _Reason) -> 
    ok.

trigger_config_retrieval() ->
    gen_server:cast(self(),retrieve_config).

trigger_key_retrieval() -> 
    gen_server:cast(self(),retrieve_keys).

timestamp() ->
    erlang:system_time(seconds).
