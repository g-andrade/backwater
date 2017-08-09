-module(backwater_client).

-include("backwater_common.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([call/5]).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type authentication() :: {signature, Key :: binary()}.
-export_type([authentication/0]).

-type config() :: config_ref() | {config_ref(), config_override()} | explicit_config().
-export_type([config/0]).

-type config_override() ::
    #{ endpoint => nonempty_binary(),
       authentication => authentication(),
       hackney_options => [hackney_option()],
       decode_unsafe_terms => boolean(),
       rethrow_remote_exceptions => boolean()
     }.
-export_type([config_override/0]).

-type config_ref() :: term().
-export_type([config_ref/0]).

-type error() :: {config_ref_not_found, ConfigRef :: config_ref()} | {hackney, term()}.
-export_type([error/0]).

-type explicit_config() ::
    #{ endpoint := nonempty_binary(),
       authentication := authentication(),
       hackney_options => [hackney_option()],
       decode_unsafe_terms => boolean(),
       rethrow_remote_exceptions => boolean()
     }.
-export_type([explicit_config/0]).

-type hackney_option() :: proplists:property(). % there's no remote type available; check hackney documentation
-export_type([hackney_option/0]).

-type result() :: backwater_http_response:t(error()).
-export_type([result/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec call(config(), unicode:chardata(), module(), atom(), [term()]) -> result().
%% @private
call(Config, Version, Module, Function, Args) ->
    ExplicitConfigGeneration = generate_config(Config),
    call_(ExplicitConfigGeneration, Version, Module, Function, Args).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-spec generate_config(config())
        -> {ok, explicit_config()} | {error, {config_ref_not_found, config_ref()}}.
generate_config(ConfigRef) when is_atom(ConfigRef) ->
    AppClientConfigs = application:get_env(backwater, clients, #{}),
    case maps:find(ConfigRef, AppClientConfigs) of
        {ok, AppClientConfig} ->
            DefaultConfig = default_config_override(),
            {ok, merge_configs(DefaultConfig, AppClientConfig)};
        error ->
            {error, {config_ref_not_found, ConfigRef}}
    end;
generate_config(ExplicitConfig) when is_map(ExplicitConfig) ->
    DefaultConfig = default_config_override(),
    {ok, merge_configs(DefaultConfig, ExplicitConfig)};
generate_config({ConfigRef, ConfigOverride}) when is_atom(ConfigRef), is_map(ConfigOverride) ->
    case generate_config(ConfigRef) of
        {ok, Config} ->
            {ok, merge_configs(Config, ConfigOverride)};
        {error, Error} ->
            {error, Error}
    end.

default_config_override() ->
    #{ hackney_options => default_hackney_options() }.

default_hackney_options() ->
    % TODO improve
    [{pool, default},
     {connect_timeout, 8000},
     {recv_timeout, 5000},
     {max_body, 10485760}].

-spec merge_configs(config_override(), config_override()) -> config_override().
merge_configs(BaseConfig, ConfigOverride) ->
    backwater_util:maps_merge_with(
      fun (hackney_options, Base, Override) ->
              backwater_util:proplists_sort_and_merge(Base, Override);
          (_Other, _Base, Override) ->
              Override
      end,
      BaseConfig,
      ConfigOverride).

-spec call_({ok, explicit_config()} | {error, {config_ref_not_found, config_ref()}},
            unicode:chardata(), module(), atom(), [term()])
        -> result().
call_({ok, ExplicitConfig}, Version, Module, Function, Args) ->
    encode_request(ExplicitConfig, Version, Module, Function, Args);
call_({error, Error}, _Version, _Module, _Function, _Args) ->
    {error, Error}.

-spec encode_request(explicit_config(), unicode:chardata(), module(), atom(), [term()])
        -> backwater_http_response:t(Error) when Error :: {hackney, term()}.
encode_request(ExplicitConfig, Version, Module, Function, Args) ->
    #{ endpoint := Endpoint, authentication := Authentication } = ExplicitConfig,
    {Request, State} =
        backwater_http_request:encode(Endpoint, Version, Module, Function, Args, Authentication),
    call_hackney(ExplicitConfig, State, Request).

-spec call_hackney(explicit_config(), backwater_http_request:state(), backwater_http_request:t())
        -> backwater_http_response:t(Error) when Error :: {hackney, term()}.
call_hackney(ExplicitConfig, RequestState, Request) ->
    {Method, Url, Headers, Body} = Request,
    #{ hackney_options := BaseHackneyOptions } = ExplicitConfig,
    MandatoryHackneyOptions = [with_body],
    HackneyOptions = backwater_util:proplists_sort_and_merge(BaseHackneyOptions, MandatoryHackneyOptions),
    Result = hackney:request(Method, Url, Headers, Body, HackneyOptions),
    handle_hackney_result(ExplicitConfig, RequestState, Result).

handle_hackney_result(ExplicitConfig, RequestState, {ok, StatusCode, Headers, Body}) ->
    Options = maps:with([decode_unsafe_terms, rethrow_remote_exceptions], ExplicitConfig),
    backwater_http_response:decode(StatusCode, Headers, Body, RequestState, Options);
handle_hackney_result(_ExplicitConfig, _RequestState, {error, Error}) ->
    {error, {hackney, Error}}.
