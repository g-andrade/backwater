-module(backwater_server).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_clear/4]).               -ignore_xref({start_clear,4}).
-export([start_tls/4]).                 -ignore_xref({start_tls,4}).
-export([stop_listener/1]).             -ignore_xref({stop_listener,1}).

%% ------------------------------------------------------------------
%% cowboy constraint Function Exports
%% ------------------------------------------------------------------

-export([arity_constraint/2]).
-export([encoded_atom_constraint/2]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(DEFAULT_CLEAR_PORT, 8080).
-define(DEFAULT_TLS_PORT, 8443).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type opts() :: backwater_cowboy_handler:opts().
-export_type([opts/0]).

-type route_constraints() :: [{version, nonempty} | {module | function | arity, fun ()}, ...].

-type route_path() :: {nonempty_string(), route_constraints(),
                       backwater_cowboy_handler, backwater_cowboy_handler:state()}.

-type route_rule() :: {'_' | nonempty_string(), [route_path(), ...]}.

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec start_clear(Ref, TransportOpts, ProtoOpts, BackwaterOpts)  -> {ok, pid()} | {error, term()}
            when Ref :: term(),
                 TransportOpts :: ranch_tcp:opts(),
                 ProtoOpts :: cowboy:opts(),
                 BackwaterOpts :: opts().

start_clear(Ref, TransportOpts0, ProtoOpts, BackwaterOpts) ->
    DefaultTransportOpts = default_transport_options(?DEFAULT_CLEAR_PORT),
    TransportOpts = backwater_util:proplists_sort_and_merge(DefaultTransportOpts, TransportOpts0),
    start_cowboy(start_clear, Ref, TransportOpts, ProtoOpts, BackwaterOpts).


-spec start_tls(Ref, TransportOpts, ProtoOpts, BackwaterOpts) -> {ok, pid()} | {error, term()}
            when Ref :: term(),
                 TransportOpts :: ranch_ssl:opts(),
                 ProtoOpts :: cowboy:opts(),
                 BackwaterOpts :: opts().

start_tls(Ref, TransportOpts0, ProtoOpts, BackwaterOpts) ->
    DefaultTransportOpts = default_transport_options(?DEFAULT_TLS_PORT),
    TransportOpts = backwater_util:proplists_sort_and_merge(DefaultTransportOpts, TransportOpts0),
    start_cowboy(start_tls, Ref, TransportOpts, ProtoOpts, BackwaterOpts).


-spec stop_listener(Ref) -> ok | {error, not_found}
            when Ref :: term().

stop_listener(Ref) ->
    cowboy:stop_listener(ref(Ref)).

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

default_transport_options(Port) ->
    [{port, Port}, {reuseaddr, true}].

-spec cowboy_route_path(backwater_cowboy_handler:state()) -> route_path().
cowboy_route_path(InitialHandlerState) ->
    BasePath = "/", % We could make this configurable.
    Constraints =
        [{version, nonempty},
         {module, fun ?MODULE:encoded_atom_constraint/2},
         {function, fun ?MODULE:encoded_atom_constraint/2},
         {arity, fun ?MODULE:arity_constraint/2}],
    {BasePath ++ ":version/:module/:function/:arity",
     Constraints, backwater_cowboy_handler, InitialHandlerState}.

-spec cowboy_route_rule(backwater_cowboy_handler:state()) -> route_rule().
cowboy_route_rule(InitialHandlerState) ->
    Host = '_', % We could make this configurable.
    {Host, [cowboy_route_path(InitialHandlerState)]}.

-spec inject_backwater_dispatch_in_proto_opts(
        cowboy:opts(), cowboy_route:dispatch_rules()) -> cowboy:opts().
inject_backwater_dispatch_in_proto_opts(ProtoOpts, BackwaterDispatch) ->
    maps:update_with(
      env,
      fun (EnvOpts) ->
              EnvOpts#{ dispatch => BackwaterDispatch }
      end,
      #{ dispatch => BackwaterDispatch },
      ProtoOpts).

-spec ref(term()) -> {backwater, term()}.
ref(Ref) ->
    {backwater, Ref}.

-spec start_cowboy(start_clear | start_tls, term(), ranch_tcp:opts() | ranch_ssl:opts(),
                   cowboy:opts(), opts())
        -> {ok, pid()} | {error, term()}.
start_cowboy(StartFunction, Ref, TransportOpts, ProtoOpts0, BackwaterOpts) ->
    case backwater_cowboy_handler:initial_state(BackwaterOpts) of
        {ok, InitialHandlerState} ->
            RouteRule = cowboy_route_rule(InitialHandlerState),
            BackwaterDispatch = cowboy_router:compile([RouteRule]),
            ProtoOpts = inject_backwater_dispatch_in_proto_opts(ProtoOpts0, BackwaterDispatch),
            cowboy:StartFunction(ref(Ref), TransportOpts, ProtoOpts);
        {error, Error} ->
            {error, Error}
    end.
