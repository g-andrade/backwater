-module(backwater_client_config).
-behaviour(gen_server).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/2]). -ignore_xref({start_link, 2}).
-export([childspec/3]).
-export([get_config/2]).

%% ------------------------------------------------------------------
%% gen_server Function Exports
%% ------------------------------------------------------------------

-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(CB_MODULE, ?MODULE).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

start_link(Ref, ClientConfig) ->
    gen_server:start_link({local, server_name(Ref)}, ?CB_MODULE, [Ref, ClientConfig], []).

childspec(Id, Ref, ClientConfig) ->
    #{ id => Id,
       start => {?MODULE, start_link, [Ref, ClientConfig]},
       restart => transient,
       type => worker,
       modules => [?MODULE] }.

get_config(Ref, ConfigOverride) ->
    ConfigTableName = config_table_name(Ref),
    BaseConfig = maps:from_list(ets:tab2list(ConfigTableName)),
    maps:merge(BaseConfig, ConfigOverride).

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

init([Ref, ClientConfig]) ->
    ConfigTableName = config_table_name(Ref),
    _ = ets:new(ConfigTableName, [named_table, protected, {read_concurrency, true}]),
    Settings = parse_config(ClientConfig),
    ets:insert(ConfigTableName, Settings),
    {ok, no_state}.

handle_call(Request, From, State) ->
    lager:debug("unhandled call ~p from ~p on state ~p",
                [Request, From, State]),
    {noreply, State}.

handle_cast(Msg, State) ->
    lager:debug("unhandled cast ~p on state ~p", [Msg, State]),
    {noreply, State}.

handle_info(Info, State) ->
    lager:debug("unhandled info ~p on state ~p", [Info, State]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

server_name(Ref) ->
    list_to_atom("backwater_" ++ backwater_ref:to_unicode_string(Ref) ++ "_client_config").

config_table_name(Ref) ->
    server_name(Ref).

default_authentication() -> none.

default_connect_timeout() -> 5000.

default_receive_timeout() -> 5000.

default_unsafe_term_decode(none) ->
    false;
default_unsafe_term_decode({basic, {_Username, _Params}}) ->
    true.

default_remote_exceptions_rethrow() ->
    false.

parse_config(ClientConfig) ->
    Endpoint = maps:get(endpoint, ClientConfig),
    Authentication = maps:get(authentication, ClientConfig, default_authentication()),
    ConnectTimeout = maps:get(connect_timeout, ClientConfig, default_connect_timeout()),
    ReceiveTimeout = maps:get(receive_timeout, ClientConfig, default_receive_timeout()),
    DecodeUnsafeTerms = maps:get(decode_unsafe_terms, ClientConfig, default_unsafe_term_decode(Authentication)),
    RethrowRemoteExceptions = maps:get(rethrow_remote_exceptions, ClientConfig, default_remote_exceptions_rethrow()),
    [{endpoint, Endpoint},
     {authentication, Authentication},
     {connect_timeout, ConnectTimeout},
     {receive_timeout, ReceiveTimeout},
     {decode_unsafe_terms, DecodeUnsafeTerms},
     {rethrow_remote_exceptions, RethrowRemoteExceptions}].
