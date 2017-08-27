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

-module(backwater_http_response).

-include_lib("hackney/include/hackney_lib.hrl").
-include("backwater_client.hrl").
-include("backwater_common.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([decode/4]).                           -ignore_xref({decode,4}).
-export([decode/5]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(DEFAULT_DECODE_UNSAFE_TERMS, false).
-define(DEFAULT_RETHROW_REMOTE_EXCEPTIONS, false).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type error() ::
        {exception, {Class :: error | exit | throw, Reason :: term(), erlang:raise_stacktrace()}} |
        {failure(), raw_response()}.
-export_type([error/0]).

-type failure() ::
        {response_authentication, response_authentication_failure()} |
        response_decode_failure() |
        remote.
-export_type([failure/0]).

-type headers() :: [{nonempty_binary(), binary()}].
-export_type([headers/0]).

-type options() ::
        #{ decode_unsafe_terms => boolean(),
           rethrow_remote_exceptions => boolean() }.
-export_type([options/0]).

-type raw_response() :: {status_code_name(), CiHeaders :: headers(), RawBody :: binary()}.
-export_type([raw_response/0]).

-type response_authentication_failure() ::
        backwater_http_signatures:response_validation_failure() |
        wrong_body_digest.
-export_type([response_authentication_failure/0]).

-type response_decode_failure() ::
        invalid_content_encoding |
        invalid_content_type |
        invalid_body.
-export_type([response_decode_failure/0]).

-type status_code() :: pos_integer().
-export_type([status_code/0]).

-type status_code_name() ::
        ok |
        bad_request |
        unauthorized |
        forbidden |
        not_found |
        not_acceptable |
        payload_too_large |
        unsupported_media_type |
        internal_error |
        {http, status_code()}.
-export_type([status_code_name/0]).

-type t() :: {ok, Value :: term()} | {error, error()} | no_return().
-export_type([t/0]).

-type t(OtherError) :: {ok, Value :: term()} | {error, error() | OtherError} | no_return().
-export_type([t/1]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec decode(StatusCode, Headers, Body, RequestState) -> Response | no_return()
            when StatusCode :: status_code(),
                 Headers :: headers(),
                 Body :: binary(),
                 RequestState :: backwater_http_request:state(),
                 Response :: t().

decode(StatusCode, Headers, Body, RequestState) ->
    decode(StatusCode, Headers, Body, RequestState, #{}).

-spec decode(StatusCode, Headers, Body, RequestState, Options) -> Response | no_return()
            when StatusCode :: status_code(),
                 Headers :: headers(),
                 Body :: binary(),
                 RequestState :: backwater_http_request:state(),
                 Options :: options(),
                 Response :: t().

decode(StatusCode, Headers, Body, RequestState, Options) ->
    CiHeaders = lists:keymap(fun backwater_util:latin1_binary_to_lower/1, 1, Headers),
    authenticate(StatusCode, CiHeaders, Body, RequestState, Options).

%% ------------------------------------------------------------------
%% Internal Function Definitions - Authentication
%% ------------------------------------------------------------------

-spec authenticate(status_code(), headers(), binary(), backwater_http_request:state(),
                   options()) -> t() | no_return().
authenticate(StatusCode, CiHeaders, Body, RequestState, Options) ->
    #{ signed_request_msg := SignedRequestMsg } = RequestState,
    ResponseMsg = backwater_http_signatures:new_response_msg(StatusCode, {ci_headers, CiHeaders}),
    case backwater_http_signatures:validate_response_signature(SignedRequestMsg, ResponseMsg)
    of
        {ok, SignedResponseMsg} ->
            authenticate_body(StatusCode, CiHeaders, Body, Options, SignedResponseMsg);
        {error, Error} ->
            failure_error({response_authentication, Error}, StatusCode, CiHeaders, Body)
    end.

-spec authenticate_body(status_code(), headers(), binary(), options(),
                        backwater_http_signatures:signed_message()) -> t().
authenticate_body(StatusCode, CiHeaders, Body, Options, SignedResponseMsg) ->
    case backwater_http_signatures:validate_signed_msg_body(SignedResponseMsg, Body) of
        true ->
            decode_(StatusCode, CiHeaders, Body, Options, SignedResponseMsg);
        false ->
            failure_error({response_authentication, wrong_body_digest}, StatusCode, CiHeaders, Body)
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Decode Response
%% ------------------------------------------------------------------

-spec decode_(status_code(), headers(), binary(), options(),
              backwater_http_signatures:signed_message()) -> t().
decode_(200 = StatusCode, CiHeaders, Body, Options, SignedResponseMsg) ->
    RethrowRemoteExceptions = rethrow_remote_exceptions(Options),
    case decode_body(CiHeaders, Body, Options, SignedResponseMsg) of
        {ok, {return, ReturnValue}} ->
            {ok, ReturnValue};
        {ok, {exception, {Class, Exception, Stacktrace}}} when RethrowRemoteExceptions ->
            erlang:raise(Class, Exception, Stacktrace);
        {ok, {exception, {Class, Exception, Stacktrace}}} ->
            {error, {exception, {Class, Exception, Stacktrace}}};
        {ok, _UnknownBodyFormat} ->
            failure_error(invalid_body, StatusCode, CiHeaders, Body);
        {error, Error} ->
            failure_error(Error, StatusCode, CiHeaders, Body)
    end;
decode_(StatusCode, CiHeaders, Body, _Options, _SignedResponseMsg) ->
    failure_error(remote, StatusCode, CiHeaders, Body).

%% ------------------------------------------------------------------
%% Internal Function Definitions - Content Encoding
%% ------------------------------------------------------------------

-spec decode_body(headers(), binary(), options(),
                           backwater_http_signatures:signed_message())
        -> {ok, term()} |
           {error, response_decode_failure()}.
decode_body(CiHeaders, Body, Options, SignedResponseMsg) ->
    ContentEncoding = get_content_encoding(CiHeaders, SignedResponseMsg),
    handle_body_content_encoding(ContentEncoding, CiHeaders, Body, Options, SignedResponseMsg).

-spec handle_body_content_encoding(ContentEncoding :: binary(),
                                   headers(), binary(), options(),
                                   backwater_http_signatures:signed_message())
        -> {ok, term()} |
           {error, response_decode_failure()}.
handle_body_content_encoding(<<"gzip">>, CiHeaders, Body, Options, SignedResponseMsg) ->
    case backwater_encoding_gzip:decode(Body, ?MAX_RESPONSE_BODY_SIZE) of
        {ok, UncompressedBody} ->
            ContentTypeLookup = get_content_type(CiHeaders, SignedResponseMsg),
            handle_body_content_type(ContentTypeLookup, UncompressedBody, Options);
        {error, _Error} ->
            {error, invalid_body}
    end;
handle_body_content_encoding(<<"identity">>, CiHeaders, Body, Options, SignedResponseMsg) ->
    ContentTypeLookup = get_content_type(CiHeaders, SignedResponseMsg),
    handle_body_content_type(ContentTypeLookup, Body, Options);
handle_body_content_encoding(_OtherEncoding, _CiHeaders, _Body, _Config, _SignedResponseMsg) ->
    {error, invalid_content_encoding}.

-spec get_content_encoding(headers(), backwater_http_signatures:signed_message()) -> binary().
get_content_encoding(CiHeaders, SignedResponseMsg) ->
    case find_header_value(?OPAQUE_BINARY(<<"content-encoding">>), CiHeaders, SignedResponseMsg) of
        {ok, ContentEncoding} ->
            ContentEncoding;
        error ->
            <<"identity">>
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Content Type
%% ------------------------------------------------------------------

-spec handle_body_content_type({ok, {nonempty_binary(), [nonempty_binary()]}} |
                               {error, invalid_content_type},
                               binary(), options())
        -> {ok, term()} |
           {error, invalid_content_type} |
           {error, invalid_body}.
handle_body_content_type({ok, {<<"application/x-erlang-etf">>, _Params}}, Body, Options) ->
    DecodeUnsafeTerms = decode_unsafe_terms(Options),
    case backwater_media_etf:decode(Body, DecodeUnsafeTerms) of
        {ok, Decoded} ->
            {ok, Decoded};
        error ->
            {error, invalid_body}
    end;
handle_body_content_type({ok, {_OtherContentType, _Params}}, _Body, _Config) ->
    {error, invalid_content_type};
handle_body_content_type({error, invalid_content_type}, _Body, _Config) ->
    {error, invalid_content_type}.

-spec get_content_type(headers(), backwater_http_signatures:signed_message())
        -> {ok, {nonempty_binary(), [nonempty_binary()]}} |
           {error, invalid_content_type}.
get_content_type(CiHeaders, SignedResponseMsg) ->
    case find_header_value(?OPAQUE_BINARY(<<"content-type">>), CiHeaders, SignedResponseMsg) of
        {ok, ContentTypeBin} ->
            case binary:split(ContentTypeBin, [<<";">>, <<" ">>, <<$\n>>, <<$\r>>],
                              [global, trim_all])
            of
                [ActualBinContentType | BinAttributes] ->
                    {ok, {ActualBinContentType, [V || V <- BinAttributes]}};
                [] ->
                    {error, invalid_content_type}
            end;
        error ->
            {error, invalid_content_type}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Utilities and Misfits
%% ------------------------------------------------------------------

-spec find_header_value(nonempty_binary(), headers(), backwater_http_signatures:signed_message())
        -> {ok, binary()} | error.
find_header_value(CiName, CiHeaders, SignedResponseMsg) ->
    case lists:keyfind(CiName, 1, CiHeaders) of
        {CiName, Value} ->
            assert_header_safety(CiName, SignedResponseMsg),
            {ok, Value};
        false ->
            error
    end.

-spec assert_header_safety(binary(), backwater_http_signatures:signed_message()) -> true | no_return().
assert_header_safety(CiName, SignedResponseMsg) ->
    backwater_http_signatures:is_header_signed_in_signed_msg(CiName, SignedResponseMsg)
    orelse error({using_unsafe_header, CiName}).

-spec decode_unsafe_terms(options()) -> boolean().
decode_unsafe_terms(Options) ->
    maps:get(decode_unsafe_terms, Options, ?DEFAULT_DECODE_UNSAFE_TERMS).

-spec rethrow_remote_exceptions(options()) -> boolean().
rethrow_remote_exceptions(Options) ->
    maps:get(rethrow_remote_exceptions, Options, ?DEFAULT_RETHROW_REMOTE_EXCEPTIONS).

-spec failure_error(failure(), status_code(), headers(), binary())
        -> {error, {failure(), raw_response()}}.
failure_error(Failure, StatusCode, CiHeaders, Body) ->
    {error, {Failure, {status_code_name(StatusCode), CiHeaders, Body}}}.

-spec status_code_name(status_code()) -> status_code_name().
status_code_name(200) -> ok;
status_code_name(400) -> bad_request;
status_code_name(401) -> unauthorized;
status_code_name(403) -> forbidden;
status_code_name(404) -> not_found;
status_code_name(405) -> method_not_allowed;
status_code_name(406) -> not_acceptable;
status_code_name(413) -> payload_too_large;
status_code_name(415) -> unsupported_media_type;
status_code_name(500) -> internal_error;
status_code_name(Unknown) -> {http, Unknown}.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Unit Tests
%% ------------------------------------------------------------------
-ifdef(TEST).

test_signatures_config() ->
    backwater_http_signatures:config( crypto:strong_rand_bytes(32) ).

test_request_msg() ->
    SignaturesConfig = test_signatures_config(),
    {SignaturesConfig, backwater_http_signatures:new_request_msg(<<"POST">>, <<"/path">>, #{})}.

test_request_state() ->
    {SignaturesConfig, RequestMsg} = test_request_msg(),
    RequestId = crypto:strong_rand_bytes(16),
    SignedRequestMsg =
        backwater_http_signatures:sign_request(SignaturesConfig, RequestMsg, <<"request body">>, RequestId),
    {SignaturesConfig, #{ signed_request_msg => SignedRequestMsg }}.

test_response(ResponseHeaders) ->
    ResponseBody = crypto:strong_rand_bytes(1024),
    {StatusCode, SignedResponseMsgHeaders, RequestState} = test_response(ResponseHeaders, ResponseBody),
    {StatusCode, SignedResponseMsgHeaders, ResponseBody, RequestState}.

test_response(ResponseHeaders, ResponseBody) ->
    {SignaturesConfig, RequestState} = test_request_state(),
    #{ signed_request_msg := SignedRequestMsg } = RequestState,
    StatusCode = 200,
    StatusCodeName = status_code_name(StatusCode),
    ResponseMsg = backwater_http_signatures:new_response_msg(StatusCode, ResponseHeaders),
    SignedResponseMsg = backwater_http_signatures:sign_response(SignaturesConfig,
                                                                ResponseMsg, ResponseBody,
                                                                SignedRequestMsg),
    SignedResponseMsgHeaders = backwater_http_signatures:list_real_msg_headers(SignedResponseMsg),
    {StatusCodeName, SignedResponseMsgHeaders, RequestState}.


invalid_signature_test() ->
    {StatusCodeName, SignedResponseMsgHeaders, ResponseBody, RequestState} = test_response(#{}),
    CorruptSignedResponseMsgHeaders =
        lists:keystore(<<"digest">>, 1, SignedResponseMsgHeaders, {<<"digest">>, <<>>}),
    ?assertMatch(
       {error, {{response_authentication, invalid_signature},
                {StatusCodeName, CorruptSignedResponseMsgHeaders, ResponseBody}}},
       decode(200, CorruptSignedResponseMsgHeaders, ResponseBody, RequestState)).

invalid_body_digest_test() ->
    {StatusCodeName, SignedResponseMsgHeaders, _ResponseBody, RequestState} = test_response(#{}),
    CorruptResponseBody = crypto:strong_rand_bytes(1024),
    ?assertMatch(
       {error, {{response_authentication, wrong_body_digest},
                {StatusCodeName, SignedResponseMsgHeaders, CorruptResponseBody}}},
       decode(200, SignedResponseMsgHeaders, CorruptResponseBody, RequestState)).

unknown_content_encoding_test() ->
    ResponseHeaders = #{ <<"content-encoding">> => <<"something">> },
    {StatusCodeName, SignedResponseMsgHeaders, ResponseBody, RequestState} =
        test_response(ResponseHeaders),
    ?assertMatch(
       {error, {invalid_content_encoding, {StatusCodeName, SignedResponseMsgHeaders, ResponseBody}}},
       decode(200, SignedResponseMsgHeaders, ResponseBody, RequestState)).

missing_content_type_test() ->
    {StatusCodeName, SignedResponseMsgHeaders, ResponseBody, RequestState} = test_response(#{}),
    ?assertMatch(
       {error, {invalid_content_type, {StatusCodeName, SignedResponseMsgHeaders, ResponseBody}}},
       decode(200, SignedResponseMsgHeaders, ResponseBody, RequestState)).

unknown_content_type_test() ->
    ResponseHeaders = #{ <<"content-type">> => <<"something/something">> },
    {StatusCodeName, SignedResponseMsgHeaders, ResponseBody, RequestState} =
        test_response(ResponseHeaders),
    ?assertMatch(
       {error, {invalid_content_type, {StatusCodeName, SignedResponseMsgHeaders, ResponseBody}}},
       decode(200, SignedResponseMsgHeaders, ResponseBody, RequestState)).

malformed_content_type_test() ->
    ResponseHeaders = #{ <<"content-type">> => <<>> },
    {StatusCodeName, SignedResponseMsgHeaders, ResponseBody, RequestState} =
        test_response(ResponseHeaders),
    ?assertMatch(
       {error, {invalid_content_type, {StatusCodeName, SignedResponseMsgHeaders, ResponseBody}}},
       decode(200, SignedResponseMsgHeaders, ResponseBody, RequestState)).

malformed_body_test() ->
    ResponseHeaders = #{ <<"content-type">> => <<"application/x-erlang-etf">> },
    {StatusCodeName, SignedResponseMsgHeaders, ResponseBody, RequestState} =
        test_response(ResponseHeaders),
    ?assertMatch(
       {error, {invalid_body, {StatusCodeName, SignedResponseMsgHeaders, ResponseBody}}},
       decode(200, SignedResponseMsgHeaders, ResponseBody, RequestState)).

malformed_compressed_body_test() ->
    ResponseHeaders = #{ <<"content-type">> => <<"application/x-erlang-etf">>,
                         <<"content-encoding">> => <<"gzip">> },
    {StatusCodeName, SignedResponseMsgHeaders, ResponseBody, RequestState} =
        test_response(ResponseHeaders),
    ?assertMatch(
       {error, {invalid_body, {StatusCodeName, SignedResponseMsgHeaders, ResponseBody}}},
       decode(200, SignedResponseMsgHeaders, ResponseBody, RequestState)).

unknown_body_format_test() ->
    ResponseHeaders = #{ <<"content-type">> => <<"application/x-erlang-etf">> },
    ResponseBody = term_to_binary(unknown),
    {StatusCodeName, SignedResponseMsgHeaders, RequestState} = test_response(ResponseHeaders, ResponseBody),
    ?assertMatch(
       {error, {invalid_body, {StatusCodeName, SignedResponseMsgHeaders, ResponseBody}}},
       decode(200, SignedResponseMsgHeaders, ResponseBody, RequestState)).

-endif.
