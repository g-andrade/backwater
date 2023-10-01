%% Copyright (c) 2017-2022 Guilherme Andrade <backwater@gandrade.net>
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

%% @reference <a target="_parent" href="https://ninenines.eu/docs/en/ranch/1.7/manual/ranch/#_opts">ranch:opts()</a> documentation
%% @reference <a target="_parent" href="https://ninenines.eu/docs/en/ranch/1.7/manual/ranch_tcp/#_opt">ranch_tcp:opt()</a> documentation
%% @reference <a target="_parent" href="https://ninenines.eu/docs/en/ranch/1.7/manual/ranch_ssl/#_opt">ranch_ssl:opt()</a> documentation
%% @reference <a target="_parent" href="https://ninenines.eu/docs/en/cowboy/2.6/manual/cowboy_http/#_options">cowboy_http:opts()</a> documentation
%% @reference hackney request options listed <a target="_parent" href="https://github.com/benoitc/hackney/blob/1.15.0/doc/hackney.md">here</a>

-module(backwater).

-include("backwater_api.hrl").
-include("backwater_common.hrl").
-include("backwater_default_tweaks.hrl").

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
%% API Function Exports (server)
%% ------------------------------------------------------------------

-export(
   [start_clear_server/2,
    start_clear_server/4,
    start_tls_server/3,
    start_tls_server/4,
    stop_server/0,
    stop_server/1,
    base_cowboy_route_parts/0 % internal
   ]).

-ignore_xref(
   [start_clear_server/2,
    start_clear_server/4,
    start_tls_server/3,
    start_tls_server/4,
    stop_server/0,
    stop_server/1
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
%% Macro Definitions (server)
%% ------------------------------------------------------------------

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

% not exported from erlang.erl
-type stack_item() ::
    {Module :: module(),
     Function :: atom(),
     Arity :: arity() | (Args :: [term()]),
     Location ::
     [{file, Filename :: string()} |
      {line, Line :: pos_integer()}]}.
-export_type([stack_item/0]).

%% ------------------------------------------------------------------
%% Type Definitions (server)
%% ------------------------------------------------------------------

-type clear_opts() :: ranch:opts() | ranch_tcp:opts().
-export_type([clear_opts/0]).

-type tls_opts() :: ranch:opts() | ranch_ssl:opts().
-export_type([tls_opts/0]).

-type http_opts() :: cowboy_http:opts().
-export_type([http_opts/0]).

-type route_path() :: {nonempty_string(), [],
                       backwater_cowboy_handler, backwater_cowboy_handler:state()}.

-type route_rule() :: {'_' | nonempty_string(), [route_path(), ...]}.

%% ------------------------------------------------------------------
%% API Function Definitions (caller)
%% ------------------------------------------------------------------

%% @doc Performs remote call on `Endpoint'.
%%
%% Returns:
%% <ul>
%% <li>`{ok, ReturnValue}' in case of success</li>
%% <li>`{error, term()}' otherwise.</li>
%% </ul>
%% @see call/5
-spec call(Endpoint, Module, Function, Args) -> Result | no_return()
        when Endpoint :: backwater_request:endpoint(),
             Module :: module(),
             Function :: atom(),
             Args :: [term()],
             Result :: call_result().
call(Endpoint, Module, Function, Args) ->
    call(Endpoint, Module, Function, Args, #{}).

%% @doc Performs remote call on `Endpoint'.
%%
%% Returns:
%% <ul>
%% <li>`{ok, ReturnValue}' in case of success</li>
%% <li>`{error, term()}' otherwise.</li>
%% </ul>
%% @see call/4
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
%% API Function Definitions (server)
%% ------------------------------------------------------------------

%% @doc Starts a cleartext cowboy listener that can handle remote calls.
%%
%% Returns:
%% <ul>
%% <li>`{ok, ServerPid}' in case of success</li>
%% <li>`{error, term()}' otherwise.</li>
%% </ul>
%% @see start_clear_server/4
-spec start_clear_server(Secret, ExposedModules)
    -> {ok, pid()} | {error, term()}
            when Secret :: binary(),
                 ExposedModules :: [backwater_module_exposure:t()].
start_clear_server(Secret, ExposedModules) ->
    start_clear_server(default, Secret, ExposedModules, #{}).

%% @doc Like `:start_clear_server/2' but one can specify the listener name  and tune settings.
%%
%% Returns:
%% <ul>
%% <li>`{ok, ServerPid}' in case of success</li>
%% <li>`{error, term()}' otherwise.</li>
%% </ul>
%% @see start_clear_server/2
-spec start_clear_server(Ref, Secret, ExposedModules, Opts)
    -> {ok, pid()} | {error, term()}
            when Ref :: term(),
                 Secret :: binary(),
                 ExposedModules :: [backwater_module_exposure:t()],
                 Opts :: backwater_cowboy_handler:opts(clear_opts() | ranch:opts(), http_opts()).
start_clear_server(Ref, Secret, ExposedModules, Opts) ->
    start_cowboy(start_clear, Ref, Secret, ExposedModules, Opts).

%% @doc Starts a TLS cowboy listener that can handle remote calls.
%%
%% Returns:
%% <ul>
%% <li>`{ok, ServerPid}' in case of success</li>
%% <li>`{error, term()}' otherwise.</li>
%% </ul>
%% @see start_tls_server/4
-spec start_tls_server(Secret, ExposedModules, TLSOpts)
    -> {ok, pid()} | {error, term()}
            when Secret :: binary(),
                 ExposedModules :: [backwater_module_exposure:t()],
                 TLSOpts :: tls_opts() | ranch:opts().
start_tls_server(Secret, ExposedModules, TLSOpts) ->
    Opts = #{ transport => TLSOpts },
    start_tls_server(default, Secret, ExposedModules, Opts).

%% @doc Like `:start_tls_server/3' but one can specify the listener name and tune (more) settings.
%%
%% Returns:
%% <ul>
%% <li>`{ok, ServerPid}' in case of success</li>
%% <li>`{error, term()}' otherwise.</li>
%% </ul>
%% @see start_tls_server/3
-spec start_tls_server(Ref, Secret, ExposedModules, Opts)
    -> {ok, pid()} | {error, term()}
            when Ref :: term(),
                 Secret :: binary(),
                 ExposedModules :: [backwater_module_exposure:t()],
                 Opts :: backwater_cowboy_handler:opts(tls_opts() | ranch:opts(), http_opts()).
start_tls_server(Ref, Secret, ExposedModules, Opts) ->
    start_cowboy(start_tls, Ref, Secret, ExposedModules, Opts).

%% @doc Stops the cowboy listener under the default name.
-spec stop_server() -> ok | {error, not_found}.
stop_server() ->
    stop_server(default).

%% @doc Stops the cowboy listener under a specific name.
-spec stop_server(Ref) -> ok | {error, not_found}
            when Ref :: term().
stop_server(Ref) ->
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
    ConnectTimeout = maps:get(connect_timeout, Options, ?DEFAULT_OPT_CONNECT_TIMEOUT),
    RecvTimeout = maps:get(recv_timeout, Options, ?DEFAULT_OPT_RECV_TIMEOUT),
    MaxEncodedResultSize =
        maps:get(max_encoded_result_size, Options, ?DEFAULT_OPT_MAX_ENCODED_RESULT_SIZE),
    [{pool, backwater_client},
     {connect_timeout, ConnectTimeout},
     {recv_timeout, RecvTimeout},
     {max_body, MaxEncodedResultSize}
    ].

%% ------------------------------------------------------------------
%% Internal Function Definitions (server)
%% ------------------------------------------------------------------

default_transport_options(true, start_clear) ->
    [{port, ?DEFAULT_CLEAR_PORT}];
default_transport_options(true, start_tls) ->
    [{port, ?DEFAULT_TLS_PORT}];
default_transport_options(false, start_clear) ->
    #{socket_opts => [{port, ?DEFAULT_CLEAR_PORT}]};
default_transport_options(false, start_tls) ->
    #{socket_opts => [{port, ?DEFAULT_TLS_PORT}]}.

-spec cowboy_route_path(backwater_cowboy_handler:state()) -> route_path().
cowboy_route_path(InitialHandlerState) ->
    Parts = base_cowboy_route_parts() ++ ["[...]"],
    Path = string:join(Parts, "/"),
    {Path, [], backwater_cowboy_handler, InitialHandlerState}.

-spec cowboy_route_rule(backwater_cowboy_handler:state()) -> route_rule().
cowboy_route_rule(InitialHandlerState) ->
    Host = '_', % We could make this configurable.
    {Host, [cowboy_route_path(InitialHandlerState)]}.

-spec ensure_num_acceptors_in_transport_opts(boolean(), clear_opts() | tls_opts() | ranch:opts())
        -> #{socket_opts := [atom() | tuple()], _ => _}.
ensure_num_acceptors_in_transport_opts(true, TransportOpts) ->
    case lists:keytake(num_acceptors, 1, TransportOpts) of
         {value, {_, NumAcceptors}, SocketOpts} ->
            #{ socket_opts => SocketOpts, num_acceptors => NumAcceptors };
        false ->
            #{ socket_opts => TransportOpts, num_acceptors => ?DEFAULT_SERVER_NB_ACCEPTORS }
    end;
ensure_num_acceptors_in_transport_opts(false, TransportOpts)
  when is_map(TransportOpts) ->
    case maps:find(num_acceptors, TransportOpts) of
        {ok, NumAcceptors} when ?is_non_neg_integer(NumAcceptors) ->
            TransportOpts;
        error ->
            TransportOpts#{ num_acceptors => ?DEFAULT_SERVER_NB_ACCEPTORS }
    end.

-spec inject_backwater_dispatch_in_map_http_opts(
        cowboy_router:dispatch_rules(), cowboy_http:opts()) -> cowboy_http:opts().
inject_backwater_dispatch_in_map_http_opts(BackwaterDispatch, ProtoOpts) ->
    maps:update_with(
      env,
      fun (EnvOpts) ->
              EnvOpts#{ dispatch => BackwaterDispatch }
      end,
      #{ dispatch => BackwaterDispatch },
      ProtoOpts).

-spec ensure_max_keepalive_in_map_http_opts(cowboy_http:opts()) -> cowboy_http:opts().
ensure_max_keepalive_in_map_http_opts(ProtoOpts) ->
    maps:merge(
      #{ max_keepalive => ?DEFAULT_SERVER_MAX_KEEPALIVE },
      ProtoOpts).

-spec ref(term()) -> {backwater, term()}.
ref(Ref) ->
    {backwater, Ref}.

-spec start_cowboy(start_clear | start_tls, term(), binary(), [backwater_module_exposure:t()],
                   (backwater_cowboy_handler:opts(ranch:opts(), http_opts()) |
                    backwater_cowboy_handler:opts(clear_opts(), http_opts()) |
                    backwater_cowboy_handler:opts(tls_opts(), http_opts())))
        -> {ok, pid()} | {error, term()}.
start_cowboy(StartFunction, Ref, Secret, ExposedModules, Opts) ->
    TransportOpts0 = maps:get(transport, Opts, #{}),
    UseLegacyTransportOpts = is_list(TransportOpts0),
    DefaultTransportOpts = default_transport_options(UseLegacyTransportOpts, StartFunction),
    TransportOpts1 =
        case UseLegacyTransportOpts of
            true -> backwater_util:proplists_sort_and_merge(DefaultTransportOpts, TransportOpts0);
            false ->
                DefaultSocketOpts = maps:get(socket_opts, DefaultTransportOpts, []),
                OverriddenSocketOpts = maps:get(socket_opts, TransportOpts0, []),
                MergedSocketOpts = backwater_util:proplists_sort_and_merge(
                                     DefaultSocketOpts, OverriddenSocketOpts),
                BaseMerged = maps:merge(DefaultTransportOpts, TransportOpts0),
                BaseMerged#{ socket_opts => MergedSocketOpts }
        end,

    HttpOpts0 = maps:get(http, Opts, #{}),
    case backwater_cowboy_handler:initial_state(Secret, ExposedModules, Opts) of
        {ok, InitialHandlerState} ->
            RouteRule = cowboy_route_rule(InitialHandlerState),
            BackwaterDispatch = cowboy_router:compile([RouteRule]),
            TransportOpts2 = ensure_num_acceptors_in_transport_opts(UseLegacyTransportOpts, TransportOpts1),
            HttpOpts1 = inject_backwater_dispatch_in_map_http_opts(BackwaterDispatch, HttpOpts0),
            HttpOpts2 = ensure_max_keepalive_in_map_http_opts(HttpOpts1),
            cowboy:StartFunction(ref(Ref), TransportOpts2, HttpOpts2);
        {error, Error} ->
            {error, Error}
    end.

%% ------------------------------------------------------------------
%% Common Test Helper Definitions
%% ------------------------------------------------------------------

-ifdef(TEST).
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
