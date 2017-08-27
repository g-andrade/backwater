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

-define(HTTP_REQUEST_ENCODING_OPTION_NAMES,
        [compression_threshold]).

-define(HTTP_RESPONSE_DECODING_OPTION_NAMES,
        [decode_unsafe_terms,
         max_encoded_result_size,
         rethrow_remote_exceptions]).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type config() ::
    #{ endpoint := nonempty_binary(),
       secret := binary(),
       hackney_opts => [hackney_option()],

       compression_threshold => non_neg_integer(),
       connect_timeout => timeout(),
       decode_unsafe_terms => boolean(),
       max_encoded_result_size => non_neg_integer(),
       recv_timeout => timeout(),
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

-spec call(Ref, Module, Function, Args) -> Result | no_return()
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
validate_config_pair({hackney_opts, HackneyOpts}) ->
    % TODO deeper validation
    is_list(HackneyOpts);
validate_config_pair({compression_threshold, CompressionThreshold}) ->
    ?is_non_neg_integer(CompressionThreshold);
validate_config_pair({connect_timeout, ConnectTimeout}) ->
    ?is_timeout(ConnectTimeout);
validate_config_pair({decode_unsafe_terms, DecodeUnsafeTerms}) ->
    is_boolean(DecodeUnsafeTerms);
validate_config_pair({max_encoded_result_size, MaxEncodedResultSize}) ->
    ?is_non_neg_integer(MaxEncodedResultSize);
validate_config_pair({recv_timeout, RecvTimeout}) ->
    ?is_timeout(RecvTimeout);
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
    Options = maps:with(?HTTP_REQUEST_ENCODING_OPTION_NAMES, Config),
    {Request, State} =
        backwater_http_request:encode(Endpoint, Module, Function, Args, Secret, Options),
    call_hackney(Config, State, Request).

-spec call_hackney(config(), backwater_http_request:state(), backwater_http_request:t())
        -> backwater_http_response:t(Error) when Error :: {hackney, term()}.
call_hackney(Config, RequestState, Request) ->
    {Method, Url, Headers, Body} = Request,
    DefaultHackneyOpts = default_hackney_opts(Config),
    ConfigHackneyOpts = maps:get(hackney_opts, Config, []),
    MandatoryHackneyOpts = [with_body],
    HackneyOpts = backwater_util:proplists_sort_and_merge(
                       [DefaultHackneyOpts, ConfigHackneyOpts, MandatoryHackneyOpts]),
    Result = hackney:request(Method, Url, Headers, Body, HackneyOpts),
    handle_hackney_result(Config, RequestState, Result).

handle_hackney_result(Config, RequestState, {ok, StatusCode, Headers, Body}) ->
    Options = maps:with(?HTTP_RESPONSE_DECODING_OPTION_NAMES, Config),
    backwater_http_response:decode(StatusCode, Headers, Body, RequestState, Options);
handle_hackney_result(_Config, _RequestState, {error, Error}) ->
    {error, {hackney, Error}}.

default_hackney_opts(Config) ->
    ConnectTimeout = maps:get(connect_timeout, Config, ?DEFAULT_OPT_CONNECT_TIMEOUT),
    RecvTimeout = maps:get(recv_timeout, Config, ?DEFAULT_OPT_RECV_TIMEOUT),
    MaxEncodedResultSize = maps:get(max_encoded_result_size, Config, ?DEFAULT_OPT_MAX_ENCODED_RESULT_SIZE),
    [{pool, backwater_client},
     {connect_timeout, ConnectTimeout},
     {recv_timeout, RecvTimeout},
     {max_body, MaxEncodedResultSize}
    ].

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
