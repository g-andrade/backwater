-module(backwater_http_response).

-include_lib("hackney/include/hackney_lib.hrl").
-include("backwater_common.hrl").

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

-type authentication_error() ::
        backwater_http_signatures:response_validation_failure() |
        wrong_body_digest.
-export_type([authentication_error/0]).

-type error() ::
        {{response_authentication, authentication_error()}, raw_error()} |
        {remote_exception, Class :: error | exit | throw, Reason :: term(), erlang:raise_stacktrace()} |
        {remote_error, raw_error()} |
        {{undecodable_response_body, binary()}, raw_error()} |
        {{unknown_content_encoding, binary()}, raw_error()} |
        {{unknown_content_type, nonempty_binary()}, raw_error()} |
        {{invalid_content_type, binary()}, raw_error()}.
-export_type([error/0]).

-type headers() :: [{nonempty_binary(), binary()}].
-export_type([headers/0]).

-type options() ::
        #{ decode_unsafe_terms => boolean(),
           rethrow_remote_exceptions => boolean() }.
-export_type([options/0]).

-type raw_error() :: {status_code_name(), (Error :: term()) | (RawBody :: binary())}.
-export_type([raw_error/0]).

-type status_code() :: pos_integer().
-export_type([status_code/0]).

-type status_code_name() ::
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

-spec decode(StatusCode, Headers, Body, RequestState) -> Response
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
%% Internal Function Definitions - Responses
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
        {error, Reason} ->
            {error, {{response_authentication, Reason}, {status_code_name(StatusCode), Body}}}
    end.

-spec authenticate_body(status_code(), headers(), binary(), options(),
                        backwater_http_signatures:signed_message()) -> t().
authenticate_body(StatusCode, CiHeaders, Body, Options, SignedResponseMsg) ->
    case backwater_http_signatures:validate_signed_msg_body(SignedResponseMsg, Body) of
        true ->
            decode_(StatusCode, CiHeaders, Body, Options, SignedResponseMsg);
        false ->
            {error, {{response_authentication, wrong_body_digest}, {status_code_name(StatusCode), Body}}}
    end.

-spec decode_(status_code(), headers(), binary(), options(),
              backwater_http_signatures:signed_message()) -> t().
decode_(200 = StatusCode, CiHeaders, Body, Options, SignedResponseMsg) ->
    RethrowRemoteExceptions = rethrow_remote_exceptions(Options),
    StatusCodeName = status_code_name(StatusCode),
    RawResponseError = {StatusCodeName, Body},
    case decode_body(CiHeaders, Body, Options, SignedResponseMsg) of
        {term, {success, ReturnValue}} ->
            {ok, ReturnValue};
        {term, {exception, Class, Exception, Stacktrace}} when RethrowRemoteExceptions ->
            erlang:raise(Class, Exception, Stacktrace);
        {term, {exception, Class, Exception, Stacktrace}} ->
            {error, {remote_exception, Class, Exception, Stacktrace}};
        {raw, Binary} ->
            {error, {remote_error, {StatusCode, Binary}}};
        {error, {unknown_content_encoding, ContentEncoding}} ->
            {error, {{unknown_content_encoding, ContentEncoding}, RawResponseError}};
        {error, {undecodable_response_body, Binary}} ->
            {error, {{undecodable_response_body, Binary}, RawResponseError}};
        {error, {unknown_content_type, RawContentType}} ->
            {error, {{unknown_content_type, RawContentType}, RawResponseError}};
        {error, {invalid_content_type, RawContentType}} ->
            {error, {{invalid_content_type, RawContentType}, RawResponseError}}
    end;
decode_(StatusCode, CiHeaders, Body, Options, SignedResponseMsg) ->
    StatusCodeName = status_code_name(StatusCode),
    RawResponseError = {StatusCodeName, Body},
    case decode_body(CiHeaders, Body, Options, SignedResponseMsg) of
        {term, Error} ->
            {error, {remote_error, {StatusCodeName, Error}}};
        {raw, Binary} ->
            {error, {remote_error, {StatusCodeName, Binary}}};
        {error, {unknown_content_encoding, ContentEncoding}} ->
            {error, {{unknown_content_encoding, ContentEncoding}, RawResponseError}};
        {error, {undecodable_response_body, Binary}} ->
            {error, {{undecodable_response_body, Binary}, RawResponseError}};
        {error, {unknown_content_type, RawContentType}} ->
            {error, {{unknown_content_type, RawContentType}, RawResponseError}};
        {error, {invalid_content_type, RawContentType}} ->
            {error, {{invalid_content_type, RawContentType}, RawResponseError}}
    end.

-spec decode_body(headers(), binary(), options(),
                           backwater_http_signatures:signed_message())
        -> {term, term()} |
           {raw, binary()} |
           {error, {invalid_content_type, binary()}} |
           {error, {undecodable_response_body, binary()}} |
           {error, {unknown_content_encoding, binary()}} |
           {error, {unknown_content_type, nonempty_binary()}}.
decode_body(CiHeaders, Body, Options, SignedResponseMsg) ->
    ContentEncodingLookup = find_content_encoding(CiHeaders, SignedResponseMsg),
    handle_body_content_encoding(ContentEncodingLookup, CiHeaders, Body, Options, SignedResponseMsg).

-spec status_code_name(status_code()) -> status_code_name().
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

%% body encoding

-spec handle_body_content_encoding({ok, binary()} | error,
                                   headers(), binary(), options(),
                                   backwater_http_signatures:signed_message())
        -> {term, term()} |
           {raw, binary()} |
           {error, {invalid_content_type, binary()}} |
           {error, {undecodable_response_body, binary()}} |
           {error, {unknown_content_encoding, binary()}} |
           {error, {unknown_content_type, nonempty_binary()}}.
handle_body_content_encoding({ok, <<"gzip">>}, CiHeaders, Body, Options, SignedResponseMsg) ->
    case backwater_encoding_gzip:decode(Body) of
        {ok, UncompressedBody} ->
            ContentTypeLookup = find_content_type(CiHeaders, SignedResponseMsg),
            handle_body_content_type(ContentTypeLookup, UncompressedBody, Options);
        {error, _Error} ->
            {error, {undecodable_response_body, Body}}
    end;
handle_body_content_encoding(Lookup, CiHeaders, Body, Options, SignedResponseMsg)
  when Lookup =:= error;
       Lookup =:= {ok, <<"identity">>} ->
    ContentTypeLookup = find_content_type(CiHeaders, SignedResponseMsg),
    handle_body_content_type(ContentTypeLookup, Body, Options);
handle_body_content_encoding({ok, OtherEncoding}, _CiHeaders, _Body, _Config, _SignedResponseMsg) ->
    {error, {unknown_content_encoding, OtherEncoding}}.

-spec find_content_encoding(headers(), backwater_http_signatures:signed_message())
        -> {ok, binary()} | error.
find_content_encoding(CiHeaders, SignedResponseMsg) ->
    find_header_value(?OPAQUE_BINARY(<<"content-encoding">>), CiHeaders, SignedResponseMsg).

%% body content type

-spec handle_body_content_type({ok, {nonempty_binary(), [nonempty_binary()]}} |
                               {error, {invalid_content_type, binary()}} |
                               {error, content_type_missing},
                               binary(), options())
        -> {term, term()} |
           {raw, binary()} |
           {error, {undecodable_response_body, binary()}} |
           {error, {unknown_content_type, nonempty_binary()}} |
           {error, {invalid_content_type, binary()}}.
handle_body_content_type({ok, {<<"application/x-erlang-etf">>, _Params}}, Body, Options) ->
    DecodeUnsafeTerms = decode_unsafe_terms(Options),
    case backwater_media_etf:decode(Body, DecodeUnsafeTerms) of
        {ok, Decoded} -> {term, Decoded};
        error -> {error, {undecodable_response_body, Body}}
    end;
handle_body_content_type({ok, {OtherContentType, _Params}}, _Body, _Config) ->
    {error, {unknown_content_type, OtherContentType}};
handle_body_content_type({error, {invalid_content_type, RawContentType}}, _Body, _Config) ->
    {error, {invalid_content_type, RawContentType}};
handle_body_content_type({error, content_type_missing}, Body, _Config) ->
    {raw, Body}.

-spec find_content_type(headers(), backwater_http_signatures:signed_message())
        -> {ok, {nonempty_binary(), [nonempty_binary()]}} |
           {error, {invalid_content_type, binary()}} |
           {error, content_type_missing}.
find_content_type(CiHeaders, SignedResponseMsg) ->
    case find_header_value(?OPAQUE_BINARY(<<"content-type">>), CiHeaders, SignedResponseMsg) of
        {ok, ContentTypeBin} ->
            case binary:split(ContentTypeBin, [<<";">>, <<" ">>, <<$\n>>, <<$\r>>],
                              [global, trim_all])
            of
                [ActualBinContentType | BinAttributes] ->
                    {ok, {ActualBinContentType, [V || V <- BinAttributes]}};
                [] ->
                    {error, {invalid_content_type, ContentTypeBin}}
            end;
        error ->
            {error, content_type_missing}
    end.

%% utilities

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
