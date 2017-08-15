-module(backwater_client).

-include("backwater_client.hrl").
-include("backwater_common.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([call/4]).                               -ignore_xref({call,4}).
-export([start/2]).                              -ignore_xref({start,2}).
-export([stop/1]).                               -ignore_xref({stop,1}).

%% ------------------------------------------------------------------
%% Common Test Helper Exports
%% ------------------------------------------------------------------

-ifdef(TEST).
-export(['_call'/5]).
-endif.

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(DEFAULT_HACKNEY_OPTIONS,
        [{pool, backwater_client},
         {connect_timeout, 8000}, % in milliseconds
         {recv_timeout, 5000}, % in milliseconds
         {max_body, ?MAX_RESPONSE_BODY_SIZE}
        ]).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type config() ::
    #{ endpoint := nonempty_binary(),
       secret := binary(),
       hackney_options => [hackney_option()],
       decode_unsafe_terms => boolean(),
       rethrow_remote_exceptions => boolean()
     }.
-export_type([config/0]).

-type hackney_error() :: {hackney, term()}.
-export_type([hackney_error/0]).

-type hackney_option() :: proplists:property(). % there's no remote type available; check hackney documentation
-export_type([hackney_option/0]).

-type result() :: backwater_http_response:t(hackney_error() | not_started).
-export_type([result/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec call(Ref, Module, Function, Args) -> Result
        when Ref :: term(),
             Module :: module(),
             Function :: atom(),
             Args :: [term()],
             Result :: result().

call(Ref, Module, Function, Args) ->
    ConfigLookup = backwater_client_instances:find_client_config(Ref),
    call_(ConfigLookup, Module, Function, Args).


-spec start(Ref, Config) -> ok | {error, Error}
        when Ref :: term(),
             Config :: config(),
             Error :: already_started | backwater_util:config_validation_error().

start(Ref, Config) ->
    case validate_config(Config) of
        {ok, ValidatedConfig} ->
            backwater_client_instances:start_client(Ref, ValidatedConfig);
        {error, Error} ->
            {error, Error}
    end.


-spec stop(Ref) -> ok | {error, not_found}
        when Ref :: term().

stop(Ref) ->
    backwater_client_instances:stop_client(Ref).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-spec validate_config(term()) -> {ok, config()} | {error, backwater_util:config_validation_error()}.
validate_config(Config) ->
    backwater_util:validate_config_map(Config, [endpoint, secret], fun validate_config_pair/1).

-spec validate_config_pair({term(), term()}) -> boolean().
validate_config_pair({endpoint, Endpoint}) ->
    is_binary(Endpoint) andalso byte_size(Endpoint) > 0;
validate_config_pair({secret, Secret}) ->
    is_binary(Secret);
validate_config_pair({hackney_options, HackneyOptions}) ->
    % TODO deeper validation
    is_list(HackneyOptions);
validate_config_pair({decode_unsafe_terms, DecodeUnsafeTerms}) ->
    is_boolean(DecodeUnsafeTerms);
validate_config_pair({rethrow_remote_exceptions, RethrowRemoteExceptions}) ->
    is_boolean(RethrowRemoteExceptions);
validate_config_pair({_K, _V}) ->
    false.

-spec call_({ok, config()} | error, module(), atom(), [term()])
        -> result().
call_({ok, Config}, Module, Function, Args) ->
    encode_request(Config, Module, Function, Args);
call_(error, _Module, _Function, _Args) ->
    {error, not_started}.

-spec encode_request(config(), module(), atom(), [term()])
        -> backwater_http_response:t(Error) when Error :: {hackney, term()}.
encode_request(Config, Module, Function, Args) ->
    #{ endpoint := Endpoint, secret := Secret } = Config,
    {Request, State} =
        backwater_http_request:encode(Endpoint, Module, Function, Args, Secret),
    call_hackney(Config, State, Request).

-spec call_hackney(config(), backwater_http_request:state(), backwater_http_request:t())
        -> backwater_http_response:t(Error) when Error :: {hackney, term()}.
call_hackney(Config, RequestState, Request) ->
    {Method, Url, Headers, Body} = Request,
    DefaultHackneyOptions = ?DEFAULT_HACKNEY_OPTIONS,
    ConfigHackneyOptions = maps:get(hackney_options, Config, []),
    MandatoryHackneyOptions = [with_body],
    HackneyOptions = backwater_util:proplists_sort_and_merge(
                       [DefaultHackneyOptions, ConfigHackneyOptions, MandatoryHackneyOptions]),
    Result = hackney:request(Method, Url, Headers, Body, HackneyOptions),
    handle_hackney_result(Config, RequestState, Result).

handle_hackney_result(Config, RequestState, {ok, StatusCode, Headers, Body}) ->
    Options = maps:with([decode_unsafe_terms, rethrow_remote_exceptions], Config),
    backwater_http_response:decode(StatusCode, Headers, Body, RequestState, Options);
handle_hackney_result(_Config, _RequestState, {error, Error}) ->
    {error, {hackney, Error}}.

%% ------------------------------------------------------------------
%% Common Test Helper Definitions
%% ------------------------------------------------------------------

-ifdef(TEST).
%% @private
'_call'(Ref, Module, Function, Args, Override) ->
    {ok, Config} = backwater_client_instances:find_client_config(Ref),
    #{ endpoint := Endpoint, secret := Secret } = Config,
    RequestEncodingOverride = maps:get(request, Override, #{}),
    {Request, State} =
        backwater_http_request:'_encode'(Endpoint, Module, Function, Args, Secret,
                                         RequestEncodingOverride),
    call_hackney(Config, State, Request).
-endif.
