%% Copyright (c) 2017-2018 Guilherme Andrade <backwater@gandrade.net>
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

%% @reference
%%
%% * [ranch:opt()](https://ninenines.eu/docs/en/ranch/1.4/manual/ranch/#_opt) documentation
%% * [ranch_tcp:opt()](https://ninenines.eu/docs/en/ranch/1.4/manual/ranch_tcp/#_opt) documentation
%% * [ranch_ssl:opt()](https://ninenines.eu/docs/en/ranch/1.4/manual/ranch_ssl/#_opt_ranch_tcp_opt_ssl_opt) documentation
%% * [cowboy_http:opts()](https://ninenines.eu/docs/en/cowboy/2.0/manual/cowboy_http/#_options) documentation

-module(backwater_server).

-include("backwater_common.hrl").
-include("backwater_api.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_clear/1]).               -ignore_xref({start_clear,1}).
-export([start_clear/4]).               -ignore_xref({start_clear,4}).
-export([start_tls/2]).                 -ignore_xref({start_tls,2}).
-export([start_tls/4]).                 -ignore_xref({start_tls,4}).
-export([stop_listener/0]).             -ignore_xref({stop_listener,0}).
-export([stop_listener/1]).             -ignore_xref({stop_listener,1}).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(DEFAULT_CLEAR_PORT, 8080).
-define(DEFAULT_TLS_PORT, 8443).
-define(DEFAULT_NB_ACCEPTORS, 20).
-define(DEFAULT_MAX_KEEPALIVE, 200). % max. nr of requests before closing a keep-alive connection

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type clear_opt() :: ranch:opt() | ranch_tcp:opt().
-export_type([clear_opt/0]).

-type clear_opts() :: [clear_opt()].
-export_type([clear_opts/0]).

-type tls_opt() :: ranch:opt() | ranch_ssl:opt().
-export_type([tls_opt/0]).

-type tls_opts() :: [tls_opt()].
-export_type([tls_opts/0]).

-type proto_opts() ::
        cowboy_http:opts() |
        [{atom(), term()}]. % for (reasonable) retro-compatibility with cowboy 1.x
-export_type([proto_opts/0]).

-type route_path() :: {nonempty_string(), [],
                       backwater_cowboy_handler, backwater_cowboy_handler:state()}.

-type route_rule() :: {'_' | nonempty_string(), [route_path(), ...]}.

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec start_clear(Config)  -> {ok, pid()} | {error, term()}
            when Config :: backwater_cowboy_handler:config().

start_clear(Config) ->
    start_clear(default, Config, [], #{}).


-spec start_clear(Ref, Config, TransportOpts, ProtoOpts)  -> {ok, pid()} | {error, term()}
            when Ref :: term(),
                 Config :: backwater_cowboy_handler:config(),
                 TransportOpts :: clear_opts(),
                 ProtoOpts :: proto_opts().

start_clear(Ref, Config, TransportOpts0, ProtoOpts) ->
    DefaultTransportOpts = default_transport_options(?DEFAULT_CLEAR_PORT),
    TransportOpts = backwater_util:proplists_sort_and_merge(DefaultTransportOpts, TransportOpts0),
    start_cowboy(start_clear, Ref, Config, TransportOpts, ProtoOpts).


-spec start_tls(Config, TransportOpts) -> {ok, pid()} | {error, term()}
            when Config :: backwater_cowboy_handler:config(),
                 TransportOpts :: tls_opts().

start_tls(Config, TransportOpts) ->
    start_tls(default, Config, TransportOpts, #{}).


-spec start_tls(Ref, Config, TransportOpts, ProtoOpts) -> {ok, pid()} | {error, term()}
            when Ref :: term(),
                 Config :: backwater_cowboy_handler:config(),
                 TransportOpts :: tls_opts(),
                 ProtoOpts :: proto_opts().

start_tls(Ref, Config, TransportOpts0, ProtoOpts) ->
    DefaultTransportOpts = default_transport_options(?DEFAULT_TLS_PORT),
    TransportOpts = backwater_util:proplists_sort_and_merge(DefaultTransportOpts, TransportOpts0),
    start_cowboy(start_tls, Ref, Config, TransportOpts, ProtoOpts).


-spec stop_listener() -> ok | {error, not_found}.

stop_listener() ->
    stop_listener(default).


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

-spec ensure_num_acceptors_in_transport_opts(clear_opts() | tls_opts()) -> clear_opts() | tls_opts().
ensure_num_acceptors_in_transport_opts(TransportOpts) ->
    backwater_util:lists_keyupdate_with(
      num_acceptors, 1,
      fun ({num_acceptors, NbAcceptors}) when ?is_non_neg_integer(NbAcceptors) ->
              {num_acceptors, NbAcceptors}
      end,
      {num_acceptors, ?DEFAULT_NB_ACCEPTORS},
      TransportOpts).

-spec map_proto_opts(proto_opts()) -> cowboy_http:opts().
map_proto_opts(Map) when is_map(Map) ->
    Map;
map_proto_opts(KvList) when is_list(KvList) ->
    maps:from_list(
      lists:keymap(
        fun ([{_, _} | _] = SubKvList) ->
                maps:from_list(SubKvList);
            (Other) ->
                Other
        end,
        2, KvList)).

-spec inject_backwater_dispatch_in_map_proto_opts(
        cowboy_router:dispatch_rules(), cowboy_http:opts()) -> cowboy_http:opts().
inject_backwater_dispatch_in_map_proto_opts(BackwaterDispatch, ProtoOpts) ->
    maps:update_with(
      env,
      fun (EnvOpts) ->
              EnvOpts#{ dispatch => BackwaterDispatch }
      end,
      #{ dispatch => BackwaterDispatch },
      ProtoOpts).

-spec ensure_max_keepalive_in_map_proto_opts(cowboy_http:opts()) -> cowboy_http:opts().
ensure_max_keepalive_in_map_proto_opts(ProtoOpts) ->
    maps:merge(
      #{ max_keepalive => ?DEFAULT_MAX_KEEPALIVE },
      ProtoOpts).

-spec ref(term()) -> {backwater, term()}.
ref(Ref) ->
    {backwater, Ref}.

-spec start_cowboy(start_clear | start_tls, term(), backwater_cowboy_handler:config(),
                   clear_opts() | tls_opts(), proto_opts())
        -> {ok, pid()} | {error, term()}.
start_cowboy(StartFunction, Ref, Config, TransportOpts1, ProtoOpts) ->
    case backwater_cowboy_handler:initial_state(Config) of
        {ok, InitialHandlerState} ->
            RouteRule = cowboy_route_rule(InitialHandlerState),
            BackwaterDispatch = cowboy_router:compile([RouteRule]),
            TransportOpts2 = ensure_num_acceptors_in_transport_opts(TransportOpts1),
            MapProtoOpts1 = map_proto_opts(ProtoOpts),
            MapProtoOpts2 = inject_backwater_dispatch_in_map_proto_opts(BackwaterDispatch, MapProtoOpts1),
            MapProtoOpts3 = ensure_max_keepalive_in_map_proto_opts(MapProtoOpts2),
            cowboy:StartFunction(ref(Ref), TransportOpts2, MapProtoOpts3);
        {error, Error} ->
            {error, Error}
    end.
