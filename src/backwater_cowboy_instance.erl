-module(backwater_cowboy_instance).
-behaviour(supervisor_bridge).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/2]).                -ignore_xref({start_link,2}).
-export([start_cowboy/3]).
-export([stop_cowboy/2]).
-export([child_spec/3]).

%% ------------------------------------------------------------------
%% supervisor_bridge Function Exports
%% ------------------------------------------------------------------

-export([init/1]).
-export([terminate/2]).

%% ------------------------------------------------------------------
%% cowboy constraint Function Exports
%% ------------------------------------------------------------------

-export([arity_constraint/2]).
-export([encoded_atom_constraint/2]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(CB_MODULE, ?MODULE).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type child_spec(Id) ::
    #{ id := Id,
       start := {?MODULE, start_link, [ref() | config(), ...]},
       restart := permanent,
       type := worker,
       modules := [?CB_MODULE, ...] }.
-export_type([child_spec/1]).

-type config() ::
        #{ secret := binary(),
           decode_unsafe_terms => boolean(),
           return_exception_stacktraces => boolean(),
           exposed_modules := [backwater_module_info:exposed_module()],
           % cowboy opts
           transport => cowboy_transport(),
           transport_options => transport_opts(),
           protocol_options => protocol_opts() }.
-export_type([config/0]).

-type protocol_opts() :: cowboy_protocol:opts().
-export_type([protocol_opts/0]).

-type ref() :: term().
-export_type([ref/0]).

-type transport_opts() :: ranch_tcp:opts() | ranch_ssl:opts().
-export_type([transport_opts/0]).

-type cowboy_transport() ::
        clear | tls |
        tcp | ssl |    % aliases #1
        http | https.  % aliases #2

-type route_constraints() :: [{version, nonempty} | {module | function | arity, fun ()}, ...].

-type route_path() :: {nonempty_string(), route_constraints(),
                       backwater_cowboy_handler, backwater_cowboy_handler:state()}.

-type route_rule() :: {'_' | nonempty_string(), [route_path(), ...]}.

-type state() :: #{ ref := ref() }.

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec child_spec(Id, ref(), config()) -> child_spec(Id) when Id :: term().
%% @private
child_spec(Id, Ref, Config) ->
    #{ id => Id,
       start => {?MODULE, start_link, [Ref, Config]},
       restart => permanent,
       type => worker,
       modules => [?CB_MODULE] }.

-spec start_cowboy(supervised | standalone, ref(), config())
        -> {ok, pid()} | {error, term()}.
%% @private
start_cowboy(Context, Ref, Config) ->
    {StartFunction, TransportOpts, BaseProtoOpts} = parse_cowboy_opts(Config),
    Dispatch = cowboy_router:compile([cowboy_route_rule(Config)]),
    ProtoOpts =
        maps:update_with(
          env,
          fun (EnvOpts) -> maps:put(dispatch, Dispatch, EnvOpts) end,
          #{ dispatch => Dispatch },
          BaseProtoOpts),
    cowboy:StartFunction({Context, Ref}, TransportOpts, ProtoOpts).

-spec start_link(ref(), config()) -> backwater_sup_util:start_link_ret().
%% @private
start_link(Ref, Config) ->
    supervisor_bridge:start_link(?CB_MODULE, [Ref, Config]).

-spec stop_cowboy(supervised | standalone, ref())
        -> ok | {error, not_found}.
%% @private
stop_cowboy(Context, Ref) ->
    cowboy:stop_listener({Context, Ref}).

%% ------------------------------------------------------------------
%% supervisor_bridge Function Definitions
%% ------------------------------------------------------------------

%% @private
-spec init([ref() | config(), ...]) -> {ok, pid(), state()} | {error, term()}.
init([Ref, Config]) ->
    case start_cowboy(supervised, Ref, Config) of
        {ok, Pid} ->
            {ok, Pid, #{ ref => Ref }};
        {error, Error} ->
            {error, Error}
    end.

%% @private
-spec terminate(term(), state()) -> ok.
terminate(_Reason, #{ ref := Ref }) ->
    ok = stop_cowboy(supervised, Ref).

%% ------------------------------------------------------------------
%% cowboy constraint Function Definitions
%% ------------------------------------------------------------------

-spec arity_constraint(forward | reverse | format_error, binary())
        -> {ok, arity()} | {error, too_small | too_large | not_a_number} | iolist().
%% @private
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

-spec encoded_atom_constraint(forward | reverse | format_error, binary())
        -> {ok, binary()} | {error, cant_convert_to_atom} | iolist().
%% @private
encoded_atom_constraint(Operation, Binary) when Operation =:= forward; Operation =:= reverse ->
    case unicode:characters_to_list(Binary, utf8) of
        String when is_list(String) ->
            case length(String) < 256 of
                true -> {ok, Binary};
                false -> {error, cant_convert_to_atom}
            end;
        _Error ->
            {error, cant_convert_to_atom}
    end;
encoded_atom_constraint(format_error, {cant_convert_to_atom, Value}) ->
    io_lib:format("Value \"~p\" cannot be converted to an atom", [Value]).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-spec cowboy_route_path(config()) -> route_path().
cowboy_route_path(Config) ->
    BasePath = "/", % We could make this configurable.
    Constraints =
        [{version, nonempty},
         {module, fun ?MODULE:encoded_atom_constraint/2},
         {function, fun ?MODULE:encoded_atom_constraint/2},
         {arity, fun ?MODULE:arity_constraint/2}],
    InitialHandlerState = backwater_cowboy_handler:initial_state(Config),
    {BasePath ++ ":version/:module/:function/:arity",
     Constraints, backwater_cowboy_handler, InitialHandlerState}.

-spec cowboy_route_rule(config()) -> route_rule().
cowboy_route_rule(Config) ->
    Host = '_', % We could make this configurable.
    {Host, [cowboy_route_path(Config)]}.

-spec parse_cowboy_opts(config())
        -> {start_clear | start_tls, transport_opts(), protocol_opts()}.
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
    TransportOpts =
        backwater_util:proplists_sort_and_merge(DefaultTransportOpts, ExtraTransportOpts),

    ProtoOpts = maps:get(protocol_options, Config, #{}),

    {StartFunction, TransportOpts, ProtoOpts}.
