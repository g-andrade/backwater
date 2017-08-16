-module(backwater_server).

-include("backwater_http_api.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_clear/4]).               -ignore_xref({start_clear,4}).
-export([start_tls/4]).                 -ignore_xref({start_tls,4}).
-export([stop_listener/1]).             -ignore_xref({stop_listener,1}).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(DEFAULT_CLEAR_PORT, 8080).
-define(DEFAULT_TLS_PORT, 8443).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type route_path() :: {nonempty_string(), [],
                       backwater_cowboy_handler, backwater_cowboy_handler:state()}.

-type route_rule() :: {'_' | nonempty_string(), [route_path(), ...]}.

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec start_clear(Ref, Config, TransportOpts, ProtoOpts)  -> {ok, pid()} | {error, term()}
            when Ref :: term(),
                 Config :: backwater_cowboy_handler:config(),
                 TransportOpts :: ranch_tcp:opts(),
                 ProtoOpts :: cowboy:opts().

start_clear(Ref, Config, TransportOpts0, ProtoOpts) ->
    DefaultTransportOpts = default_transport_options(?DEFAULT_CLEAR_PORT),
    TransportOpts = backwater_util:proplists_sort_and_merge(DefaultTransportOpts, TransportOpts0),
    start_cowboy(start_clear, Ref, Config, TransportOpts, ProtoOpts).


-spec start_tls(Ref, Config, TransportOpts, ProtoOpts) -> {ok, pid()} | {error, term()}
            when Ref :: term(),
                 Config :: backwater_cowboy_handler:config(),
                 TransportOpts :: ranch_ssl:opts(),
                 ProtoOpts :: cowboy:opts().

start_tls(Ref, Config, TransportOpts0, ProtoOpts) ->
    DefaultTransportOpts = default_transport_options(?DEFAULT_TLS_PORT),
    TransportOpts = backwater_util:proplists_sort_and_merge(DefaultTransportOpts, TransportOpts0),
    start_cowboy(start_tls, Ref, Config, TransportOpts, ProtoOpts).


-spec stop_listener(Ref) -> ok | {error, not_found}
            when Ref :: term().

stop_listener(Ref) ->
    cowboy:stop_listener(ref(Ref)).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

default_transport_options(Port) ->
    [{port, Port}].

-spec cowboy_route_path(backwater_cowboy_handler:state()) -> route_path().
cowboy_route_path(InitialHandlerState) ->
    Path = io_lib:format("~s/~s/[...]", [?BACKWATER_HTTP_API_BASE_ENDPOINT, ?BACKWATER_HTTP_API_VERSION]),
    {Path, [], backwater_cowboy_handler, InitialHandlerState}.

-spec cowboy_route_rule(backwater_cowboy_handler:state()) -> route_rule().
cowboy_route_rule(InitialHandlerState) ->
    Host = '_', % We could make this configurable.
    {Host, [cowboy_route_path(InitialHandlerState)]}.

-spec inject_backwater_dispatch_in_proto_opts(
        cowboy_route:dispatch_rules(), cowboy:opts()) -> cowboy:opts().
inject_backwater_dispatch_in_proto_opts(BackwaterDispatch, ProtoOpts) ->
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

-spec start_cowboy(start_clear | start_tls, term(), backwater_cowboy_handler:config(),
                   ranch_tcp:opts() | ranch_ssl:opts(), cowboy:opts())
        -> {ok, pid()} | {error, term()}.
start_cowboy(StartFunction, Ref, Config, TransportOpts, ProtoOpts0) ->
    case backwater_cowboy_handler:initial_state(Config) of
        {ok, InitialHandlerState} ->
            RouteRule = cowboy_route_rule(InitialHandlerState),
            BackwaterDispatch = cowboy_router:compile([RouteRule]),
            ProtoOpts = inject_backwater_dispatch_in_proto_opts(BackwaterDispatch, ProtoOpts0),
            cowboy:StartFunction(ref(Ref), TransportOpts, ProtoOpts);
        {error, Error} ->
            {error, Error}
    end.
