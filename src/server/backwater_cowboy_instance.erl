-module(backwater_cowboy_instance).
-behaviour(gen_server).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/2]). -ignore_xref({start_link, 2}).
-export([child_spec/3]).
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

-type config() :: backwater_cowboy_handler:backwater_opts().
-export_type([config/0]).

-type child_spec(Id) ::
        #{ id := Id,
           start := {?MODULE, start_link, [term() | config, ...]},
           restart := transient,
           shutdown := 5000,
           type := worker,
           modules := [?MODULE, ...] }.

-export_type([child_spec/1]).

-type route_rule() :: {'_' | nonempty_string(), [route_path(), ...]}.
-export_type([route_rule/0]).

-type route_path() :: {nonempty_string(), backwater_cowboy_handler,
                       [backwater_cowboy_handler:backwater_opts(), ...]}.
-export_type([route_path/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec start_link(term(), config()) -> {ok, pid()} | ignore | {error, term()}.
start_link(Ref, ServerConfig) ->
    gen_server:start_link({local, server_name(Ref)}, ?CB_MODULE, [Ref, ServerConfig], []).

-spec child_spec(term(), term(), config()) -> child_spec(term()).
child_spec(Id, Ref, ServerConfig) ->
    #{ id => Id,
       start => {?MODULE, start_link, [Ref, ServerConfig]},
       restart => transient,
       shutdown => 5000, % in order of 'terminate/2' to be called (condition I)
       type => worker,
       modules => [?MODULE] }.

-spec cowboy_route_rule(backwater_cowboy_handler:backwater_opts()) -> route_rule().
cowboy_route_rule(BackwaterOpts) ->
    Host = maps:get(host, BackwaterOpts, '_'),
    {Host, [cowboy_route_path(BackwaterOpts)]}.

-spec cowboy_route_path(backwater_cowboy_handler:backwater_opts()) -> route_path().
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

-spec server_name(term()) -> atom().
server_name(Ref) ->
    list_to_atom("backwater_" ++ backwater_ref:to_unicode_string(Ref) ++ "_cowboy_instance").

-spec start_cowboy(term(), config()) -> {ok, pid()}.
start_cowboy(Ref, ServerConfig) ->
    {StartFunction, NbAcceptors, TransOpts, BaseProtoOpts,
     BackwaterOpts} = parse_config(ServerConfig),

    Dispatch = cowboy_router:compile([cowboy_route_rule(BackwaterOpts)]),
    ProtoOpts =
        backwater_util:lists_keyupdate_with(
          env, 1, BaseProtoOpts,
          fun ({env, EnvOpts}) ->
                  {env, lists:keystore(dispatch, 1, EnvOpts, {dispatch, Dispatch})}
          end,
          {env, [{dispatch, Dispatch}]}),

    cowboy:StartFunction(Ref, NbAcceptors, TransOpts, ProtoOpts).

-spec stop_cowboy(term()) -> ok | {error, not_found}.
stop_cowboy(Ref) ->
    cowboy:stop_listener(Ref).

-spec parse_config(config())
        -> {start_http | start_https,
            pos_integer(),
            backwater_cowboy_handler:backwater_transport_opts(),
            backwater_cowboy_handler:backwater_protocol_opts(),
            backwater_cowboy_handler:backwater_opts()}.
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
