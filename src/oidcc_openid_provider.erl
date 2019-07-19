-module(oidcc_openid_provider).
-behaviour(gen_server).

%% API.
-export([start_link/2]).
-export([stop/1]).
-export([is_issuer/2]).
-export([is_ready/1]).
-export([get_config/1]).
-export([update_config/1]).
-export([update_and_get_keys/1]).
-export([get_error/1]).


%% gen_server.
-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).
-export([terminate/2]).
-export([code_change/3]).

-record(state, {
          ready = false,
          error = undefined,
          key_requests = [],
          registration_params = #{},

          id = undefined,
          name = undefined,
          desc = undefined,
          client_id = undefined,
          client_secret = undefined,
          request_scopes = undefined,
          issuer = undefined,
          config_ep = undefined,
          config = #{},
          keys = [],
          lasttime_updated = undefined,
          local_endpoint = undefined,
          meta_data = #{},
          static_extend_url = #{},

          config_tries = 1,
          config_deadline = undefined,
          http_result = undefined,
          retrieving = undefined,
          request_id = undefined,

          extra_config = #{}
         }).

%% API.

-spec start_link(Id :: binary(), Config::map()) -> {ok, pid()}.
start_link(Id, Config) ->
    gen_server:start_link(?MODULE, {Id, Config}, []).

-spec stop(Pid ::pid()) -> ok.
stop(Pid) ->
    gen_server:cast(Pid, stop).

-spec update_config(Pid :: pid() ) -> ok.
update_config(Pid) ->
    gen_server:call(Pid, update_config).

-spec is_issuer(Issuer :: binary(), Pid :: pid() ) -> true | false.
is_issuer(Issuer, Pid) ->
    gen_server:call(Pid, {is_issuer, Issuer}).

-spec is_ready(Pid :: pid() ) -> true | false.
is_ready(Pid) ->
    gen_server:call(Pid, is_ready).

-spec get_config( Pid :: pid() ) -> {ok, Config :: map()}.
get_config( Pid) ->
    gen_server:call(Pid, get_config).

-spec update_and_get_keys( Pid :: pid() ) -> {ok, Keys :: map()}.
update_and_get_keys(Pid) ->
    gen_server:call(Pid, update_and_get_keys, 60000).

-spec get_error( Pid :: pid() ) -> {ok, term()}.
get_error( Pid) ->
    gen_server:call(Pid, get_error).

%% timeout in seconds
-define(TIMEOUT, 60).
-define(GEN_TIMEOUT, ?TIMEOUT * 1000).

%% gen_server.
init({Id, Config}) ->

    #{name := Name,
      description := Description,
      request_scopes := Scopes,
      issuer_or_endpoint := IssuerOrEndpoint,
      local_endpoint := LocalEndpoint,
      static_extend_url := ExtendUrl
     } = Config,
    RegistrationParams = maps:get(registration_params, Config, #{}),
    ClientSecret = maps:get(client_secret, Config, undefined),
    ClientId = case ClientSecret of
                   undefined ->
                       undefined;
                   _ ->
                       maps:get(client_id, Config, undefined)
               end,
    trigger_config_retrieval(),
    DeleteKeys = [name, description, request_scopes, issuer_or_endpoint,
                  local_endpoint, client_secret, client_id],
    ExtraConfig = maps:without(DeleteKeys, Config),
    ConfigEndpoint = to_config_endpoint(IssuerOrEndpoint),
    Issuer = config_ep_to_issuer(ConfigEndpoint),
    {ok, #state{id = Id, name = Name, desc = Description, client_id = ClientId,
                client_secret = ClientSecret, config_ep = ConfigEndpoint,
                request_scopes = Scopes, local_endpoint = LocalEndpoint,
                issuer = Issuer, registration_params = RegistrationParams,
                static_extend_url = ExtendUrl, extra_config = ExtraConfig
               }}.

handle_call(get_config, _From, State) ->
    trigger_config_retrieval_if_needed(State),
    Conf = create_config(State),
    {reply, {ok, Conf}, State, ?GEN_TIMEOUT};
handle_call(update_and_get_keys, From, #state{key_requests = Requests}=State) ->
    trigger_key_retrieval(),
    NewRequests = [ From | Requests ],
    NewState = State#state{key_requests = NewRequests},
    {noreply, NewState, ?GEN_TIMEOUT};
handle_call(get_error, _From, #state{error=Error} = State) ->
    trigger_config_retrieval_if_needed(State),
    {reply, {ok, Error}, State, ?GEN_TIMEOUT};
handle_call(update_config, _From, State) ->
    ok = trigger_config_retrieval(),
    {reply, ok, State#state{config_tries=0}, ?GEN_TIMEOUT};
handle_call({is_issuer, Issuer}, _From, #state{config=Config}=State) ->
    trigger_config_retrieval_if_needed(State),
    Result = (Issuer == maps:get(issuer, Config, undefined)),
    {reply, Result , State, ?GEN_TIMEOUT};
handle_call(is_ready, _From, #state{ready=Ready}=State) ->
    trigger_config_retrieval_if_needed(State),
    {reply, Ready, State, ?GEN_TIMEOUT};
handle_call(_Request, _From, State) ->
    trigger_config_retrieval_if_needed(State),
    {reply, ignored, State, ?GEN_TIMEOUT}.


handle_cast(retrieve_config, #state{ request_id = undefined,
                                     config_ep=ConfigEndpoint} = State) ->
    NewState = http_async_get(config, ConfigEndpoint, [], State),
    {noreply, NewState, ?GEN_TIMEOUT};
handle_cast(retrieve_config, State) ->
    trigger_config_retrieval_if_needed(State),
    {noreply, State#state{config_deadline=deadline_in(120)}, ?GEN_TIMEOUT};
handle_cast(retrieve_keys, #state{ request_id = undefined,
                                   config = Config} = State) ->
    trigger_config_retrieval_if_needed(State),
    NewState =
        case maps:get(jwks_uri, Config, undefined) of
            undefined ->
                State#state{error=no_jwk_uri};
            KeyEndpoint ->
                Header = [{"accept",
                           "application/json;q=0.7,application/jwk+json,application/jwk-set+json"}],
                http_async_get(keys, KeyEndpoint, Header, State)
        end,
    {noreply, NewState, ?GEN_TIMEOUT};
handle_cast(retrieve_keys, State) ->
    trigger_config_retrieval_if_needed(State),
    trigger_key_retrieval(),
    {noreply, State, ?GEN_TIMEOUT};
handle_cast(register_if_needed, #state{ request_id = undefined,
                                        client_id = undefined,
                                        local_endpoint=LocalEndpoint,
                                        registration_params=RegistrationParams,
                                        config = Config
                                      } = State) ->
    trigger_config_retrieval_if_needed(State),
    BasicParams = #{application_type => <<"web">>,
                    redirect_uris => [LocalEndpoint]},
    RegParams = maps:merge(RegistrationParams, BasicParams),
    Body = jsone:encode(RegParams),
    RegistrationEndpoint = maps:get(registration_endpoint, Config),
    NewState = http_async_post(registration, RegistrationEndpoint, [],
                                   "application/json", Body, State),
    {noreply, NewState, ?GEN_TIMEOUT};
handle_cast(register_if_needed, State) ->
    trigger_config_retrieval_if_needed(State),
    {noreply, State#state{ready=true}, ?GEN_TIMEOUT};
handle_cast(stop, State) ->
    {stop, normal, State};
handle_cast(_Msg, State) ->
    trigger_config_retrieval_if_needed(State),
    {noreply, State, ?GEN_TIMEOUT}.


handle_info({http, {RequestId, Result}}, #state{request_id = RequestId} =
                State) ->
    trigger_config_retrieval_if_needed(State),
    NewState = handle_http_result(State#state{http_result = Result}),
    {noreply, NewState, ?GEN_TIMEOUT};
handle_info(timeout, State) ->
    trigger_config_retrieval_if_needed(State),
    {noreply, State, ?GEN_TIMEOUT}.

http_async_get(Type, Url, Header, State) ->
    case oidcc_http_util:async_http(get, Url, Header) of
        {ok, RequestId} ->
            State#state{request_id = RequestId, retrieving=Type};
        Error ->
            State#state{error = Error}
    end.

http_async_post(Type, Url, Header, ContentType, Body, State) ->
    case oidcc_http_util:async_http(post, Url, Header, ContentType, Body) of
        {ok, RequestId} ->
            State#state{request_id = RequestId, retrieving=Type};
        Error ->
            State#state{error = Error}
    end.


terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


handle_http_result(true, _,  Header, Body, config, State) ->
    handle_config(Body, Header, State);
handle_http_result(true, _,  Header, Body, keys, State) ->
    handle_keys(Body, Header, State);
handle_http_result(true, _, Header, Body, registration, State) ->
    handle_registration(Body, Header, State);
handle_http_result(false, Status, _Header, Body, Retrieve, State) ->
    State#state{error = {retrieving, Retrieve, Status, Body},
                config_deadline = deadline_in(600)}.


handle_http_result(#state{http_result={error, Reason}} = State) ->
    handle_http_client_crash(Reason, State);
handle_http_result(#state{retrieving=Retrieve,
                          http_result={{_Proto, Status, _StatusName}, Header,
                                       InBody}
                         } = State) ->
    GoodStatus = (Status >= 200) and (Status < 300),
    {ok, Body} = oidcc_http_util:uncompress_body_if_needed(InBody, Header),
    handle_http_result(GoodStatus, Status, Header, Body, Retrieve, State).



create_config(#state{id = Id, desc = Desc, client_id = ClientId,
                     client_secret = ClientSecret, config_ep = ConfEp,
                     config=Config, keys = Keys, issuer = Issuer,
                     lasttime_updated = LastTimeUpdated, ready = Ready,
                     local_endpoint = LocalEndpoint, name = Name,
                     request_scopes = Scopes, meta_data = MetaData,
                     config_deadline = ConfDeadline, extra_config = ExtraConfig,
                     static_extend_url = StaticExtUrl
                    }) ->
    StateList = [{id, Id}, {name, Name}, {description, Desc},
                 {client_id, ClientId}, {client_secret, ClientSecret},
                 {config_endpoint, ConfEp}, {lasttime_updated, LastTimeUpdated},
                 {ready, Ready}, {local_endpoint, LocalEndpoint}, {keys, Keys},
                 {request_scopes, Scopes}, {issuer, Issuer},
                 {meta_data, MetaData}, {config_deadline, ConfDeadline},
                 {extra_config, ExtraConfig}, {static_extend_url, StaticExtUrl}
                ],
    maps:merge(Config, maps:from_list(StateList)).



handle_config(Data, Header, #state{issuer=Issuer} = State) ->
    Config = decode_json(Data),
    ConfIssuer = maps:get(issuer, Config, undefined),

    SameIssuer = is_same_issuer(ConfIssuer, Issuer),
    AuthCodeFlow = supports_auth_code(Config),
    case {SameIssuer, AuthCodeFlow} of
        {true, true} ->
            Deadline = header_to_deadline(Header),
            trigger_registration(),
            State#state{config = Config, issuer=ConfIssuer,
                        request_id=undefined, config_deadline=Deadline};
        {true, false} ->
            Error = no_authcode_support,
            State#state{error = Error, ready=false, request_id=undefined};
        _ ->
            Deadline = deadline_in(600),
            Error = {bad_issuer_config, Issuer, ConfIssuer, Data},
            State#state{error = Error, ready=false, request_id=undefined,
                        config_deadline=Deadline}
    end.


supports_auth_code(#{response_types_supported := ResponseTypes} = Config) ->
    Code = <<"code">>,
    AuthCode = <<"authorization_code">>,
    GrantTypes = maps:get(grant_types_supported, Config,
                          [AuthCode, <<"implicit">>]),
    CodeResponse = lists:member(Code, ResponseTypes),
    AuthGrant = lists:member(AuthCode, GrantTypes),
    CodeResponse and AuthGrant;
supports_auth_code(_) ->
    false.



header_to_deadline(Header) ->
    Cache = lists:keyfind(<<"cache-control">>, 1, Header),
    Delta =
        try
            cache_deadline(Cache)
        catch _:_ ->
                3600
        end,
    deadline_in(Delta).

cache_deadline({_, Cache}) ->
    Entries = binary:split(Cache, [<<",">>, <<"=">>, <<" ">>],
                           [global, trim_all]),
    MaxAge = fun(Entry, true) ->
                     binary_to_integer(Entry);
                (<<"max-age">>, _) ->
                     true;
                (_, Res) ->
                     Res
             end,
    lists:foldl(MaxAge, false, Entries).

deadline_in(Seconds) ->
    timestamp() + Seconds.


handle_keys(Data, _Header, State) ->
    %TODO: maybe also implement a keys deadline
    KeyConfig=decode_json(Data),
    KeyList = maps:get(keys, KeyConfig, []),
    NewState = State#state{keys  = KeyList, lasttime_updated = timestamp(),
                           request_id = undefined, key_requests = []},
    send_key_replies(KeyList, State),
    case length(KeyList) > 0 of
        true ->
            NewState;
        false ->
            NewState#state{error = {no_keys, Data}}
    end.

send_key_replies(Keys, #state{key_requests = Requests}) ->
    Send = fun(From, _) ->
                   gen_server:reply(From, {ok, Keys})
           end,
    lists:foldl(Send, ok, Requests).


handle_registration(Data, _Header, State) ->
    %TODO: implement update at expire data/time or retrieval when needed
    MetaData=decode_json(Data),
    ClientId = maps:get(client_id, MetaData, undefined),
    ClientSecret = maps:get(client_secret, MetaData, undefined),
    ClientSecretExpire = maps:get(client_secret_expires_at, MetaData,
                                  undefined),
    case is_binary(ClientId) and is_binary(ClientSecret)
        and is_number(ClientSecretExpire) of
        true ->
            State#state{meta_data  = MetaData, client_id = ClientId,
                        client_secret = ClientSecret, ready = true,
                        lasttime_updated = timestamp(), request_id = undefined};
        false ->
            State#state{error=no_clientid, meta_data=MetaData, ready = false,
                        client_id=undefined, client_secret = undefined,
                        request_id = undefined}
    end.


decode_json(Data) ->
    try
        jsone:decode(Data, [{keys, attempt_atom}, {object_format, map}])
    catch error:badarg ->
            #{}
    end.




handle_http_client_crash(Reason, #state{config_tries=Tries,
                                        retrieving=Type} = State) ->
    MaxRetries = application:get_env(oidcc, provider_max_tries, 5),
    case Tries >= MaxRetries of
        true ->
            State#state{error = Reason};
        false ->
            case Type of
                keys ->
                    trigger_key_retrieval();
                config ->
                    trigger_config_retrieval()
            end,
            State#state{request_id=undefined,
                        http_result={}, config_tries=Tries+1,
                        config_deadline = deadline_in(300)}
    end.


trigger_config_retrieval() ->
    gen_server:cast(self(), retrieve_config).

trigger_config_retrieval_if_needed(#state{config_deadline=Deadline} = State)
  when is_integer(Deadline) ->
    Soon = timestamp() + ?TIMEOUT,
    case Soon >= Deadline of
        true ->
            trigger_config_retrieval(),
            {ok, State#state{config_deadline = undefined}};
        _ ->
            {ok, State}
    end;
trigger_config_retrieval_if_needed(State) ->
    {ok, State}.

trigger_key_retrieval() ->
    gen_server:cast(self(), retrieve_keys).

trigger_registration() ->
    gen_server:cast(self(), register_if_needed).

timestamp() ->
    erlang:system_time(seconds).

to_config_endpoint(IssuerOrEndpoint) ->
    Slash = <<"/">>,
    Config = <<".well-known/openid-configuration">>,
    ConfigS = << Slash/binary, Config/binary >>,
    Pos = byte_size(IssuerOrEndpoint) - 33,
    case binary:match(IssuerOrEndpoint, ConfigS) of
        {Pos, 33} ->
            Endpoint = IssuerOrEndpoint,
            Endpoint;
       _  ->
            Issuer = IssuerOrEndpoint,
            case binary:last(Issuer) of
                $/ -> << Issuer/binary, Config/binary>>;
                _ -> << Issuer/binary, ConfigS/binary>>
            end
    end.

config_ep_to_issuer(ConfigEp) ->
    [Issuer] = binary:split(ConfigEp, [<<"/.well-known/openid-configuration">>],
                 [trim_all, global]),
    Issuer.

is_same_issuer(Config, Issuer) ->
    Slash = <<"/">>,
    IssuerSlash = << Issuer/binary, Slash/binary >>,
    (Config =:= Issuer) or (Config =:= IssuerSlash).
