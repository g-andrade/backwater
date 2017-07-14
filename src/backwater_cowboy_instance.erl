-module(backwater_cowboy_instance).
-behaviour(gen_server).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/2]). -ignore_xref({start_link, 2}).
-export([childspec/3]).
-export([cowboy_route_rule/1]).
-export([cowboy_route_path/1]).

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
-define(SERVER, ?MODULE).

%% ------------------------------------------------------------------
%% Record Definitions
%% ------------------------------------------------------------------

-record(state, {
          ref :: term(),
          monitor :: reference()
         }).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

start_link(Ref, ServerConfig) ->
    gen_server:start_link({local, server_name(Ref)}, ?CB_MODULE, [Ref, ServerConfig], []).

childspec(Id, Ref, ServerConfig) ->
    #{ id => Id,
       start => {?MODULE, start_link, [Ref, ServerConfig]},
       restart => transient,
       shutdown => 5000, % in order of 'terminate/2' to be called (condition I)
       type => worker,
       modules => [?MODULE] }.

cowboy_route_rule(BackwaterOpts) ->
    Host = maps:get(host, BackwaterOpts, '_'),
    {Host, [cowboy_route_path(BackwaterOpts)]}.

cowboy_route_path(BackwaterOpts) ->
    BasePath = maps:get(base_path, BackwaterOpts, "/rpcall/"),
    {BasePath ++ ":version/:module/:function/:arity",
     backwater_cowboy_handler, [BackwaterOpts]}.

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

init([Ref, ServerConfig]) ->
    process_flag(trap_exit, true), % in order for 'terminate/2' to be called (condition II)
    {ok, Pid} = start_cowboy(Ref, ServerConfig),
    {ok, #state{ ref = Ref, monitor = monitor(process, Pid) }}.

handle_call(_Request, _From, State) ->
    {noreply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'DOWN', Ref, process, _Pid, Reason}, #state{ ref = Ref } = State) ->
    {stop, Reason, State};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{ ref = Ref }) ->
    ok = stop_cowboy(Ref);
terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

server_name(Ref) ->
    list_to_atom("backwater_" ++ backwater_ref:to_unicode_string(Ref) ++ "_cowboy_instance").

start_cowboy(Ref, ServerConfig) ->
    {StartFunction, NbAcceptors, TransOpts, BaseProtoOpts,
     BackwaterOpts} = parse_config(ServerConfig),

    Dispatch = cowboy_router:compile([cowboy_route_rule(BackwaterOpts)]),
    ProtoOpts =
        lists_keyupdate(
          env, 1, BaseProtoOpts,
          fun ({env, EnvOpts}) ->
                  {env, lists:keystore(dispatch, 1, EnvOpts, {dispatch, Dispatch})}
          end,
          {env, [{dispatch, Dispatch}]}),

    cowboy:StartFunction(Ref, NbAcceptors, TransOpts, ProtoOpts).

stop_cowboy(Ref) ->
    cowboy:stop_listener(Ref).

lists_keyupdate(Key, N, TupleList, Fun, Initial) ->
    case lists:keyfind(Key, N, TupleList) of
        Tuple when is_tuple(Tuple) ->
            NewTuple = Fun(Tuple),
            lists:keystore(Key, N, TupleList, NewTuple);
        false ->
            lists:keystore(Key, N, TupleList, Initial)
    end.

parse_config(ServerConfig) ->
    CowboyOptions = maps:get(cowboy, ServerConfig, #{}),
    StartFunction =
        case maps:get(protocol, CowboyOptions, http) of
            http -> start_http;
            https -> start_https
            %spdy -> start_spdy % this would make things confusing for now - hackney doesn't support it
        end,
    NbAcceptors = maps:get(number_of_acceptors, CowboyOptions, 100),
    TransOpts = maps:get(transport_options, CowboyOptions, []),
    DefaultProtoOpts = [{compress, true}],
    ExtraProtoOpts = lists:keysort(1, maps:get(protocol_options, CowboyOptions, [])),
    ProtoOpts = lists:keymerge(1, ExtraProtoOpts, DefaultProtoOpts),
    BackwaterOpts = maps:with([unauthenticated_access, authenticated_access], ServerConfig),
    {StartFunction, NbAcceptors, TransOpts, ProtoOpts, BackwaterOpts}.
