%% Copyright (c) 2017 Guilherme Andrade <backwater@gandrade.net>
%%
%% Permission is hereby granted, free of charge, to any person obtaining a
%% copy  of this software and associated documentation files (the "Software"),
%% to deal in the Software without restriction, including without limitation
%% the rights to use, copy, modify, merge, publish, distribute, sublicense,
%% and/or sell copies of the Software, and to permit persons to whom the
%% Software is furnished to do so, subject to the following conditions:
%%
%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.
%%
%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
%% DEALINGS IN THE SOFTWARE.

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
-define(DEFAULT_NB_ACCEPTORS, 10).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type clear_opt() ::
    ranch:opt() |
    ranch_tcp:opt() |
    {num_acceptors, non_neg_integer()}. % XXX: part of ranch:opt() as of cowboy 2.0
-export_type([clear_opt/0]).

-type clear_opts() :: [clear_opt()].
-export_type([clear_opts/0]).

-type tls_opt() ::
    ranch:opt() |
    ranch_ssl:opt() |
    {num_acceptors, non_neg_integer()}. % XXX: part of ranch:opt() as of cowboy 2.0
-export_type([tls_opt/0]).

-type tls_opts() :: [tls_opt()].
-export_type([tls_opts/0]).

-type proto_opts() :: cowboy_protocol:opts(). % XXX: it's a map as of cowboy 2.0
-export_type([proto_opts/0]).

-type route_path() :: {nonempty_string(), [],
                       backwater_cowboy_handler, backwater_cowboy_handler:state()}.

-type route_rule() :: {'_' | nonempty_string(), [route_path(), ...]}.

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec start_clear(Ref, Config, TransportOpts, ProtoOpts)  -> {ok, pid()} | {error, term()}
            when Ref :: term(),
                 Config :: backwater_cowboy_handler:config(),
                 TransportOpts :: clear_opts(),
                 ProtoOpts :: proto_opts().

start_clear(Ref, Config, TransportOpts0, ProtoOpts) ->
    DefaultTransportOpts = default_transport_options(?DEFAULT_CLEAR_PORT),
    TransportOpts = backwater_util:proplists_sort_and_merge(DefaultTransportOpts, TransportOpts0),
    start_cowboy(start_http, Ref, Config, TransportOpts, ProtoOpts).


-spec start_tls(Ref, Config, TransportOpts, ProtoOpts) -> {ok, pid()} | {error, term()}
            when Ref :: term(),
                 Config :: backwater_cowboy_handler:config(),
                 TransportOpts :: tls_opts(),
                 ProtoOpts :: proto_opts().

start_tls(Ref, Config, TransportOpts0, ProtoOpts) ->
    DefaultTransportOpts = default_transport_options(?DEFAULT_TLS_PORT),
    TransportOpts = backwater_util:proplists_sort_and_merge(DefaultTransportOpts, TransportOpts0),
    start_cowboy(start_https, Ref, Config, TransportOpts, ProtoOpts).


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
        cowboy_route:dispatch_rules(), proto_opts()) -> proto_opts().
inject_backwater_dispatch_in_proto_opts(BackwaterDispatch, ProtoOpts) ->
    backwater_util:lists_keyupdate_with(
      env, 1,
      fun ({env, EnvOpts}) ->
              {env, lists:keystore(dispatch, 1, EnvOpts, {dispatch, BackwaterDispatch})}
      end,
      {env, [{dispatch, BackwaterDispatch}]},
      ProtoOpts).

-spec ref(term()) -> {backwater, term()}.
ref(Ref) ->
    {backwater, Ref}.

-spec start_cowboy(start_http | start_https, term(), backwater_cowboy_handler:config(),
                   clear_opts() | tls_opts(), proto_opts())
        -> {ok, pid()} | {error, term()}.
start_cowboy(StartFunction, Ref, Config, TransportOpts, ProtoOpts0) ->
    case backwater_cowboy_handler:initial_state(Config) of
        {ok, InitialHandlerState} ->
            RouteRule = cowboy_route_rule(InitialHandlerState),
            BackwaterDispatch = cowboy_router:compile([RouteRule]),
            NbAcceptors = proplists:get_value(num_acceptors, TransportOpts, ?DEFAULT_NB_ACCEPTORS),
            ProtoOpts = inject_backwater_dispatch_in_proto_opts(BackwaterDispatch, ProtoOpts0),
            Cowboy1TransportOpts = lists:keydelete(num_acceptors, 1, TransportOpts),
            cowboy:StartFunction(ref(Ref), NbAcceptors, Cowboy1TransportOpts, ProtoOpts);
        {error, Error} ->
            {error, Error}
    end.
