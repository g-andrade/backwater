-module(backwater_client).

-include("backwater_common.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([call/5]).                               -ignore_xref({call,5}).
-export([start/2]).                              -ignore_xref({start,2}).
-export([stop/1]).                               -ignore_xref({stop,1}).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(DEFAULT_HACKNEY_OPTIONS,
        [{pool, backwater_client},
         {connect_timeout, 8000}, % in milliseconds
         {recv_timeout, 5000}, % in milliseconds
         {max_body, (10 * (1 bsl 20))} % in bytes
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

-type config_error() ::
    {invalid_config_parameter, {term(), term()}} |
    {missing_mandatory_config_parameters, [endpoint | secret, ...]} |
    invalid_config.
-export_type([config_error/0]).

-type hackney_error() :: {hackney, term()}.
-export_type([hackney_error/0]).

-type hackney_option() :: proplists:property(). % there's no remote type available; check hackney documentation
-export_type([hackney_option/0]).

-type result() :: backwater_http_response:t(hackney_error() | not_started).
-export_type([result/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec call(Ref, Version, Module, Function, Args) -> Result
        when Ref :: term(),
             Version :: unicode:chardata(),
             Module :: module(),
             Function :: atom(),
             Args :: [term()],
             Result :: result().

call(Ref, Version, Module, Function, Args) ->
    ConfigLookup = backwater_client_instances:find_client_config(Ref),
    call_(ConfigLookup, Version, Module, Function, Args).


-spec start(Ref, Config) -> ok | {error, Error}
        when Ref :: term(),
             Config :: config(),
             Error :: already_started | config_error().

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

-spec validate_config(term()) -> {ok, config()} | {error, config_error()}.
validate_config(#{ endpoint := _, secret := _ } = Config) ->
    ConfigList = maps:to_list(Config),
    ValidationResult = backwater_util:lists_allmap(fun validate_config_pair/1, ConfigList),
    case ValidationResult of
        {true, ValidatedConfigList} ->
            {ok, maps:from_list(ValidatedConfigList)};
        {false, InvalidSetting} ->
            {error, {invalid_config_parameter, InvalidSetting}}
    end;
validate_config(#{} = Config) ->
    Missing = [endpoint, secret] -- maps:keys(Config),
    {error, {missing_mandatory_config_parameters, Missing}};
validate_config(_Config) ->
    {error, invalid_config}.

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

-spec call_({ok, config()} | error, unicode:chardata(), module(), atom(), [term()])
        -> result().
call_({ok, Config}, Version, Module, Function, Args) ->
    encode_request(Config, Version, Module, Function, Args);
call_(error, _Version, _Module, _Function, _Args) ->
    {error, not_started}.

-spec encode_request(config(), unicode:chardata(), module(), atom(), [term()])
        -> backwater_http_response:t(Error) when Error :: {hackney, term()}.
encode_request(Config, Version, Module, Function, Args) ->
    #{ endpoint := Endpoint, secret := Secret } = Config,
    {Request, State} =
        backwater_http_request:encode(Endpoint, Version, Module, Function, Args, Secret),
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
