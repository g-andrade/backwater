-module(backwater_server_instance).
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
-type state() :: unstarted | #state{}.

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type config() ::
        #{ authentication := {basic, binary(), binary()},
           decode_unsafe_terms => boolean(),
           return_exception_stacktraces => boolean(),
           % cowboy opts
           transport => cowboy_transport(),
           transport_options => transport_opts(),
           protocol_options => protocol_opts() }.
-export_type([config/0]).

-type cowboy_transport() ::
        clear | tls |
        tcp | ssl |    % aliases #1
        http | https.  % aliases #2

-type transport_opts() :: ranch_tcp:opts() | ranch_ssl:opts().
-export_type([transport_opts/0]).

-type protocol_opts() :: cowboy_protocol:opts().
-export_type([protocol_opts/0]).

-type child_spec(Id) ::
        #{ id := Id,
           start := {?MODULE, start_link, [term() | config(), ...]},
           restart := transient,
           shutdown := 5000,
           type := worker,
           modules := [?MODULE, ...] }.
-export_type([child_spec/1]).

-type route_rule() :: {'_' | nonempty_string(), [route_path(), ...]}.
-export_type([route_rule/0]).

-type route_path() :: {nonempty_string(), route_constraints(),
                       backwater_cowboy_handler, backwater_cowboy_handler:state()}.
-export_type([route_path/0]).

-type route_constraints() :: [{version, nonempty} | {module | function | arity, fun ()}, ...].
-export_type([route_constraints/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec start_link(term(), config()) -> {ok, pid()} | ignore | {error, term()}.
start_link(Ref, Config) ->
    gen_server:start_link({local, server_name(Ref)}, ?CB_MODULE, [Ref, Config], []).

-spec child_spec(term(), term(), config()) -> child_spec(term()).
child_spec(Id, Ref, Config) ->
    #{ id => Id,
       start => {?MODULE, start_link, [Ref, Config]},
       restart => transient,
       shutdown => 5000, % in order of 'terminate/2' to be called (condition I)
       type => worker,
       modules => [?MODULE] }.

-spec cowboy_route_rule(config()) -> route_rule().
cowboy_route_rule(Config) ->
    Host = maps:get(host, Config, '_'), % TODO document?
    {Host, [cowboy_route_path(Config)]}.

-spec cowboy_route_path(config()) -> route_path().
cowboy_route_path(Config) ->
    BasePath = maps:get(base_path, Config, "/rpcall/"), % TODO document?
    Constraints =
        [{version, nonempty},
         {module, fun encoded_atom_constraint/2},
         {function, fun encoded_atom_constraint/2},
         {arity, fun arity_constraint/2}],
    InitialHandlerState = backwater_cowboy_handler:initial_state(Config),
    {BasePath ++ ":version/:module/:function/:arity",
     Constraints, backwater_cowboy_handler, InitialHandlerState}.

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

-spec init([term() | config(), ...]) -> {ok, unstarted}.
init([Ref, Config]) ->
    process_flag(trap_exit, true), % in order for 'terminate/2' to be called (condition II)
    gen_server:cast(self(), {start, Ref, Config}),
    {ok, unstarted}.

-spec handle_call(term(), {pid(), reference()}, state()) -> {noreply, state()}.
handle_call(_Request, _From, State) ->
    {noreply, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast({start, Ref, Config}, unstarted) ->
    {ok, Pid} = start_cowboy(Ref, Config),
    {noreply, #state{ ref = Ref, monitor = monitor(process, Pid) }};
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(term(), state()) -> {noreply, state()}.
handle_info({'DOWN', Ref, process, _Pid, Reason}, #state{ ref = Ref } = State) ->
    {stop, Reason, State};
handle_info(_Info, State) ->
    {noreply, State}.

-spec terminate(term(), state()) -> ok.
terminate(_Reason, #state{ ref = Ref }) ->
    ok = stop_cowboy(Ref);
terminate(_Reason, _State) ->
    ok.

-spec code_change(term(), state(), term()) -> {ok, state()}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-spec server_name(term()) -> atom().
server_name(Ref) ->
    list_to_atom("backwater_" ++ backwater_ref:to_unicode_string(Ref) ++ "_server_instance").

-spec start_cowboy(term(), config()) -> {ok, pid()}.
start_cowboy(Ref, Config) ->
    {StartFunction, TransportOpts, BaseProtoOpts} = parse_cowboy_opts(Config),
    Dispatch = cowboy_router:compile([cowboy_route_rule(Config)]),
    ProtoOpts =
        maps:update_with(
          env,
          fun (EnvOpts) -> maps:put(dispatch, Dispatch, EnvOpts) end,
          #{ dispatch => Dispatch },
          BaseProtoOpts),
    cowboy:StartFunction(Ref, TransportOpts, ProtoOpts).

-spec stop_cowboy(term()) -> ok | {error, not_found}.
stop_cowboy(Ref) ->
    cowboy:stop_listener(Ref).

-spec parse_cowboy_opts(config())
        -> {start_clear | start_tls,
            backwater_cowboy_handler:backwater_transport_opts(),
            backwater_cowboy_handler:backwater_protocol_opts()}.
parse_cowboy_opts(Config) ->
    StartFunction =
        case maps:get(transport, Config, clear) of
            clear -> start_clear;
            tcp   -> start_clear;
            http  -> start_clear;
            tls   -> start_tls;
            ssl   -> start_tls;
            https -> start_tls
        end,

    DefaultTransportOpts = [{port,8080}],
    ExtraTransportOpts = maps:get(transport_options, Config, []),
    TransportOpts = backwater_util:proplists_sort_and_merge(DefaultTransportOpts, ExtraTransportOpts),

    DefaultProtoOpts = #{ stream_handlers => [cowboy_compress_h, cowboy_stream_h] },
    ExtraProtoOpts = maps:get(protocol_options, Config, #{}),
    ProtoOpts = maps:merge(ExtraProtoOpts, DefaultProtoOpts),

    {StartFunction, TransportOpts, ProtoOpts}.

-spec encoded_atom_constraint(forward | reverse | format_error, binary())
        -> {ok, binary()} | {error, cant_convert_to_atom} | iolist().
encoded_atom_constraint(Operation, Binary) when Operation =:= forward; Operation =:= reverse ->
    % TODO deal with UTF8?
    case byte_size(Binary) < 256 of
        true -> {ok, Binary};
        false -> {error, cant_convert_to_atom}
    end;
encoded_atom_constraint(format_error, {cant_convert_to_atom, Value}) ->
    io_lib:format("Value \"~p\" cannot be converted to an atom", [Value]).

-spec arity_constraint(forward | reverse | format_error, binary())
        -> {ok, arity()} | {error, too_small | too_large | not_a_number} | iolist().
arity_constraint(forward, Binary) ->
    try binary_to_integer(Binary) of
        Integer when Integer < 0 ->
            {error, too_small};
        Integer when Integer > 255 ->
            {error, too_large};
        Arity ->
            {ok, Arity}
    catch
        error:badarg ->
            {error, not_a_number}
    end;
arity_constraint(reverse, Integer) when not  is_integer(Integer) ->
    {error, not_a_number};
arity_constraint(reverse, Integer) when Integer < 0 ->
    {error, too_small};
arity_constraint(reverse, Integer) when Integer > 255 ->
    {error, too_large};
arity_constraint(reverse, Arity) ->
    {ok, integer_to_binary(Arity)};
arity_constraint(format_error, {too_small, Value}) ->
    io_lib:format("Value \"~p\" is too small to be interpreted as arity", [Value]);
arity_constraint(format_error, {too_large, Value}) ->
    io_lib:format("Value \"~p\" is too large to be interpreted as arity", [Value]);
arity_constraint(format_error, {not_a_number, Value}) ->
    io_lib:format("Value \"~p\" is not a number", [Value]).
