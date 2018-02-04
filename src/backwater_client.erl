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
%% * hackney request options listed [here](https://github.com/benoitc/hackney/blob/master/doc/hackney.md)

-module(backwater_client).

-include("backwater_client.hrl").
-include("backwater_common.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([call/4]).                               -ignore_xref({call,4}).
-export([call/5]).                               -ignore_xref({call,5}).

%% ------------------------------------------------------------------
%% Common Test Helper Exports
%% ------------------------------------------------------------------

-ifdef(TEST).
-export(['_call'/6]).
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

-type options() ::
    #{ hackney_opts => [hackney_option()],
       compression_threshold => non_neg_integer(),
       connect_timeout => timeout(),
       decode_unsafe_terms => boolean(),
       max_encoded_result_size => non_neg_integer(),
       recv_timeout => timeout(),
       rethrow_remote_exceptions => boolean()
     }.
-export_type([options/0]).

-type hackney_error() :: {hackney, term()}.
-export_type([hackney_error/0]).

-type hackney_option() :: proplists:property().
-export_type([hackney_option/0]).

-type result() :: backwater_response:t(hackney_error() | not_started).
-export_type([result/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec call(Endpoint, Module, Function, Args) -> Result | no_return()
        when Endpoint :: backwater_request:endpoint(),
             Module :: module(),
             Function :: atom(),
             Args :: [term()],
             Result :: result().

call(Endpoint, Module, Function, Args) ->
    call(Endpoint, Module, Function, Args, #{}).


-spec call(Endpoint, Module, Function, Args, Options) -> Result | no_return()
        when Endpoint :: backwater_request:endpoint(),
             Module :: module(),
             Function :: atom(),
             Args :: [term()],
             Options :: options(),
             Result :: result().

call(Endpoint, Module, Function, Args, Options) ->
    encode_request(Endpoint, Module, Function, Args, Options).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-spec encode_request(backwater_request:endpoint(), module(), atom(), [term()], options())
        -> backwater_response:t(Error) when Error :: {hackney, term()}.
encode_request(Endpoint, Module, Function, Args, Options) ->
    RequestOptions = maps:with(?HTTP_REQUEST_ENCODING_OPTION_NAMES, Options),
    {Request, State} =
        backwater_request:encode(Endpoint, Module, Function, Args, RequestOptions),
    call_hackney(Request, State, Options).

-spec call_hackney(backwater_request:t(), backwater_request:state(), options())
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
    MaxEncodedResultSize = maps:get(max_encoded_result_size, Options, ?DEFAULT_OPT_MAX_ENCODED_RESULT_SIZE),
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
