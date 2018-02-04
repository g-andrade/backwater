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
%% * hackney request options listed [here](https://github.com/benoitc/hackney/blob/master/doc/hackney.md)

-module(backwater).

-include("backwater_api.hrl").
-include("backwater_client.hrl").
-include("backwater_common.hrl").

%% ------------------------------------------------------------------
%% API Function Exports (caller)
%% ------------------------------------------------------------------

-export(
   [call/4,
    call/5
   ]).

-ignore_xref(
   [call/4,
    call/5
   ]).

%% ------------------------------------------------------------------
%% API Function Exports (listener)
%% ------------------------------------------------------------------

-export(
   [start_clear_listener/1,
    start_clear_listener/4,
    start_tls_listener/2,
    start_tls_listener/4,
    stop_listener/0,
    stop_listener/1,
    base_cowboy_route_parts/0 % internal
   ]).

-ignore_xref(
   [start_clear_listener/1,
    start_clear_listener/4,
    start_tls_listener/2,
    start_tls_listener/4,
    stop_listener/0,
    stop_listener/1
   ]).

-dialyzer(
   {nowarn_function,
    [base_cowboy_route_parts/0
    ]}).

%% ------------------------------------------------------------------
%% Common Test Helper Exports
%% ------------------------------------------------------------------

-ifdef(TEST).
-export(['_call'/6]).
-endif.

%% ------------------------------------------------------------------
%% Macro Definitions (caller)
%% ------------------------------------------------------------------

-define(HTTP_REQUEST_ENCODING_OPTION_NAMES,
        [compression_threshold]).

-define(HTTP_RESPONSE_DECODING_OPTION_NAMES,
        [decode_unsafe_terms,
         max_encoded_result_size,
         rethrow_remote_exceptions]).

%% ------------------------------------------------------------------
%% Macro Definitions (listener)
%% ------------------------------------------------------------------

-define(DEFAULT_NB_ACCEPTORS, 20).
-define(DEFAULT_MAX_KEEPALIVE, 200). % max. nr of requests before closing a keep-alive connection

-define(HTTP_API_API_BASE_ENDPOINT, "/backwater"). % we could make this configurable
-define(HTTP_API_API_VERSION, "1").

%% ------------------------------------------------------------------
%% Type Definitions (caller)
%% ------------------------------------------------------------------

-type call_opts() ::
    #{ hackney_opts => [hackney_option()],
       compression_threshold => non_neg_integer(),
       connect_timeout => timeout(),
       decode_unsafe_terms => boolean(),
       max_encoded_result_size => non_neg_integer(),
       recv_timeout => timeout(),
       rethrow_remote_exceptions => boolean()
     }.
-export_type([call_opts/0]).

-type hackney_error() :: {hackney, term()}.
-export_type([hackney_error/0]).

-type hackney_option() :: proplists:property().
-export_type([hackney_option/0]).

-type call_result() :: backwater_response:t(hackney_error()).
-export_type([call_result/0]).

%% ------------------------------------------------------------------
%% Type Definitions (listener)
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
%% API Function Definitions (caller)
%% ------------------------------------------------------------------

-spec call(Endpoint, Module, Function, Args) -> Result | no_return()
        when Endpoint :: backwater_request:endpoint(),
             Module :: module(),
             Function :: atom(),
             Args :: [term()],
             Result :: call_result().

call(Endpoint, Module, Function, Args) ->
    call(Endpoint, Module, Function, Args, #{}).

-spec call(Endpoint, Module, Function, Args, Options) -> Result | no_return()
        when Endpoint :: backwater_request:endpoint(),
             Module :: module(),
             Function :: atom(),
             Args :: [term()],
             Options :: call_opts(),
             Result :: call_result().

call(Endpoint, Module, Function, Args, Options) ->
    encode_request(Endpoint, Module, Function, Args, Options).

%% ------------------------------------------------------------------
%% API Function Definitions (listener)
%% ------------------------------------------------------------------

-spec start_clear_listener(Config)  -> {ok, pid()} | {error, term()}
            when Config :: backwater_cowboy_handler:config().
start_clear_listener(Config) ->
    start_clear_listener(default, Config, [], #{}).

-spec start_clear_listener(Ref, Config, TransportOpts, ProtoOpts)  -> {ok, pid()} | {error, term()}
            when Ref :: term(),
                 Config :: backwater_cowboy_handler:config(),
                 TransportOpts :: clear_opts(),
                 ProtoOpts :: proto_opts().
start_clear_listener(Ref, Config, TransportOpts0, ProtoOpts) ->
    DefaultTransportOpts = default_transport_options(?DEFAULT_CLEAR_PORT),
    TransportOpts = backwater_util:proplists_sort_and_merge(DefaultTransportOpts, TransportOpts0),
    start_cowboy(start_clear, Ref, Config, TransportOpts, ProtoOpts).


-spec start_tls_listener(Config, TransportOpts) -> {ok, pid()} | {error, term()}
            when Config :: backwater_cowboy_handler:config(),
                 TransportOpts :: tls_opts().
start_tls_listener(Config, TransportOpts) ->
    start_tls_listener(default, Config, TransportOpts, #{}).


-spec start_tls_listener(Ref, Config, TransportOpts, ProtoOpts) -> {ok, pid()} | {error, term()}
            when Ref :: term(),
                 Config :: backwater_cowboy_handler:config(),
                 TransportOpts :: tls_opts(),
                 ProtoOpts :: proto_opts().
start_tls_listener(Ref, Config, TransportOpts0, ProtoOpts) ->
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

-spec base_cowboy_route_parts() -> [nonempty_string()].
%% @private
base_cowboy_route_parts() ->
    [?HTTP_API_API_BASE_ENDPOINT, ?HTTP_API_API_VERSION].

%% ------------------------------------------------------------------
%% Internal Function Definitions (caller)
%% ------------------------------------------------------------------

-spec encode_request(backwater_request:endpoint(), module(), atom(), [term()], call_opts())
        -> backwater_response:t(Error) when Error :: {hackney, term()}.
encode_request(Endpoint, Module, Function, Args, Options) ->
    RequestOptions = maps:with(?HTTP_REQUEST_ENCODING_OPTION_NAMES, Options),
    {Request, State} =
        backwater_request:encode(Endpoint, Module, Function, Args, RequestOptions),
    call_hackney(Request, State, Options).

-spec call_hackney(backwater_request:t(), backwater_request:state(), call_opts())
        -> backwater_response:t(Error) when Error :: {hackney, term()}.
call_hackney(Request, RequestState, Options) ->
    #{ http_params := HttpParams, full_url := FullUrl } = Request,
    #{ method := Method, headers := Headers, body := Body } = HttpParams,
    DefaultHackneyOpts = default_hackney_opts(Options),
    ExplicitHackneyOpts = maps:get(hackney_opts, Options, []),
    MandatoryHackneyOpts = [with_body],
    HackneyOpts = backwater_util:proplists_sort_and_merge(
                    [DefaultHackneyOpts, ExplicitHackneyOpts, MandatoryHackneyOpts]),
    Result = hackney:request(Method, FullUrl, Headers, Body, HackneyOpts),
    handle_hackney_result(Result, RequestState, Options).

handle_hackney_result({ok, StatusCode, Headers, Body}, RequestState, Options) ->
    ResponseOptions = maps:with(?HTTP_RESPONSE_DECODING_OPTION_NAMES, Options),
    backwater_response:decode(StatusCode, Headers, Body, RequestState, ResponseOptions);
handle_hackney_result({error, Error}, _RequestState, _Options) ->
    {error, {hackney, Error}}.

default_hackney_opts(Options) ->
    ConnectTimeout = maps:get(connect_timeout, Options, ?DEFAULT_CLIENT_OPT_CONNECT_TIMEOUT),
    RecvTimeout = maps:get(recv_timeout, Options, ?DEFAULT_CLIENT_OPT_RECV_TIMEOUT),
    MaxEncodedResultSize = maps:get(max_encoded_result_size, Options, ?DEFAULT_CLIENT_OPT_MAX_ENCODED_RESULT_SIZE),
    [{pool, backwater_client},
     {connect_timeout, ConnectTimeout},
     {recv_timeout, RecvTimeout},
     {max_body, MaxEncodedResultSize}
    ].

%% ------------------------------------------------------------------
%% Internal Function Definitions (listener)
%% ------------------------------------------------------------------

default_transport_options(Port) ->
    [{port, Port}].

-spec cowboy_route_path(backwater_cowboy_handler:state()) -> route_path().
cowboy_route_path(InitialHandlerState) ->
    Parts = base_cowboy_route_parts() ++ ["[...]"],
    Path = string:join(Parts, "/"),
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

%% ------------------------------------------------------------------
%% Common Test Helper Definitions
%% ------------------------------------------------------------------

-ifdef(TEST).
%% @private
'_call'(Endpoint, Module, Function, Args, Options, Override) ->
    RequestEncodingOverride = maps:get(request, Override, #{}),
    PrevDictionaryKeyValue = put(override, RequestEncodingOverride),
    {Request, RequestState} = backwater_request:encode(Endpoint, Module, Function, Args, Options),
    try
        call_hackney(Request, RequestState, Options)
    after
        put(override, PrevDictionaryKeyValue)
    end.
-endif.
