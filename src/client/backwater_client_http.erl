-module(backwater_client_http).

-include_lib("hackney/include/hackney_lib.hrl").
-include("../backwater_common.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([encode_request/5]).
-export([decode_response/4]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(COMPRESSION_THRESHOLD, 300). % bytes

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type stateful_request() :: {request(), request_state()}.
-export_type([stateful_request/0]).

-opaque request_state() ::
        #{ config := backwater_client_config:t(),
           signed_request_msg := backwater_http_signatures:signed_message() }.

-export_type([request_state/0]).

-type request() ::
        {Method :: nonempty_binary(),
         Url :: nonempty_binary(),
         Headers :: nonempty_headers(),
         Body :: binary()}.

-export_type([request/0]).

-type status_code() :: pos_integer().
-export_type([status_code/0]).

-type headers() :: [{nonempty_binary(), binary()}].
-export_type([headers/0]).

-type nonempty_headers() :: [{nonempty_binary(), binary()}, ...].
-export_type([nonempty_headers/0]).

-type response() :: {ok, Value :: term()} | {error, response_error()} | no_return().
-export_type([response/0]).

-type response(OtherError) :: {ok, Value :: term()} | {error, response_error() | OtherError} | no_return().
-export_type([response/1]).

-type response_error() ::
        {{response_authentication, response_authentication_error()}, raw_response_error()} |
        {remote_exception, Class :: error | exit | throw, Reason :: term(), erlang:raise_stacktrace()} |
        {remote_error, raw_response_error()} |
        {{undecodable_response_body, binary()}, raw_response_error()} |
        {{unknown_content_encoding, binary()}, raw_response_error()} |
        {{unknown_content_type, nonempty_binary()}, raw_response_error()} |
        {{invalid_content_type, binary()}, raw_response_error()}.

-export_type([response_error/0]).

-type raw_response_error() :: {status_code_name(), (Error :: term()) | (RawBody :: binary())}.
-export_type([raw_response_error/0]).

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

-type response_authentication_error() ::
        wrong_body_digest |
        backwater_http_signatures:response_validation_failure().

-export_type([response_authentication_error/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec encode_request(Version, Module, Function, Args, Config) -> Request
            when Version :: unicode:chardata(),
                 Module :: module(),
                 Function :: atom(),
                 Args :: [term()],
                 Config :: backwater_client_config:t(),
                 Request :: stateful_request().

encode_request(Version, Module, Function, Args, Config) ->
    Body = backwater_media_etf:encode(Args),
    Arity = length(Args),
    Method = ?OPAQUE_BINARY(<<"POST">>),
    Url = request_url(Version, Module, Function, Arity, Config),
    MediaType = ?OPAQUE_BINARY(<<"application/x-erlang-etf">>),
    Headers =
        [{?OPAQUE_BINARY(<<"accept">>), ?OPAQUE_BINARY(<<MediaType/binary>>)},
         {?OPAQUE_BINARY(<<"accept-encoding">>), ?OPAQUE_BINARY(<<"gzip">>)},
         {?OPAQUE_BINARY(<<"content-type">>), ?OPAQUE_BINARY(<<MediaType/binary>>)}],
    encode_request_with_compression(Method, Url, Headers, Body, Config).


-spec decode_response(StatusCode, Headers, Body, RequestState) -> Response
            when StatusCode :: status_code(),
                 Headers :: headers(),
                 Body :: binary(),
                 RequestState :: request_state(),
                 Response :: response().

decode_response(StatusCode, Headers, Body, RequestState) ->
    CiHeaders = lists:keymap(fun backwater_util:latin1_binary_to_lower/1, 1, Headers),
    authenticate_response(StatusCode, CiHeaders, Body, RequestState).

%% ------------------------------------------------------------------
%% Internal Function Definitions - Requests
%% ------------------------------------------------------------------

-spec request_url(unicode:chardata(), module(), atom(), arity(),
                  backwater_client_config:t()) -> nonempty_binary().
request_url(Version, Module, Function, Arity, Config) ->
    #{ endpoint := Endpoint } = Config,
    PathComponents =
        [hackney_url:urlencode(unicode:characters_to_binary(Version)),
         hackney_url:urlencode(atom_to_binary(Module, utf8)),
         hackney_url:urlencode(atom_to_binary(Function, utf8)),
         integer_to_binary(Arity)],
    QueryString = <<>>,
    hackney_url:make_url(Endpoint, PathComponents, QueryString).

-spec encode_request_with_compression(nonempty_binary(), nonempty_binary(),
                                      nonempty_headers(), binary(),
                                      backwater_client_config:t()) -> stateful_request().
encode_request_with_compression(Method, Url, Headers, Body, Config)
  when byte_size(Body) > ?COMPRESSION_THRESHOLD ->
    CompressedBody = backwater_encoding_gzip:encode(Body),
    UpdatedHeaders = [{<<"content-encoding">>, <<"gzip">>} | Headers],
    encode_request_with_auth(Method, Url, UpdatedHeaders, CompressedBody, Config);
encode_request_with_compression(Method, Url, Headers, Body, Config) ->
    encode_request_with_auth(Method, Url, Headers, Body, Config).

-spec encode_request_with_auth(nonempty_binary(), nonempty_binary(),
                               nonempty_headers(), binary(),
                               backwater_client_config:t()) -> stateful_request().
encode_request_with_auth(Method, Url, Headers1, Body, #{ authentication := {signature, Key} } = Config) ->
    PathWithQs = url_path_with_qs(Url),
    SignaturesConfig = backwater_http_signatures:config(Key),
    RequestMsg = backwater_http_signatures:new_request_msg(Method, PathWithQs, Headers1),
    RequestId = base64:encode( crypto:strong_rand_bytes(16) ),
    SignedRequestMsg = backwater_http_signatures:sign_request(SignaturesConfig, RequestMsg, Body, RequestId),
    Headers2 = backwater_http_signatures:list_real_msg_headers(SignedRequestMsg),
    Request = {?OPAQUE_BINARY(Method), ?OPAQUE_BINARY(Url), Headers2, Body},
    State = #{ config => Config, signed_request_msg => SignedRequestMsg },
    {Request, State}.

-spec url_path_with_qs(nonempty_binary()) -> binary().
url_path_with_qs(Url) ->
    HackneyUrl = hackney_url:parse_url(Url),
    #hackney_url{ path = Path, qs = Qs } = HackneyUrl,
    case Qs =:= <<>> of
        true -> Path;
        false -> <<Path/binary, "?", Qs/binary>>
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Responses
%% ------------------------------------------------------------------

-spec authenticate_response(status_code(), headers(), binary(), request_state()) -> response().
authenticate_response(StatusCode, CiHeaders, Body, RequestState) ->
    #{ config := Config, signed_request_msg := SignedRequestMsg } = RequestState,
    #{ authentication := {signature, Key} } = Config,
    SignaturesConfig = backwater_http_signatures:config(Key),
    ResponseMsg = backwater_http_signatures:new_response_msg(StatusCode, {ci_headers, CiHeaders}),
    case backwater_http_signatures:validate_response_signature(SignaturesConfig, ResponseMsg, SignedRequestMsg)
    of
        {ok, SignedResponseMsg} ->
            authenticate_response_body(StatusCode, CiHeaders, Body, Config, SignedResponseMsg);
        {error, Reason} ->
            {error, {{response_authentication, Reason}, {status_code_name(StatusCode), Body}}}
    end.

-spec authenticate_response_body(status_code(), headers(), binary(), backwater_client_config:t(),
                                 backwater_http_signatures:signed_message()) -> response().
authenticate_response_body(StatusCode, CiHeaders, Body, Config, SignedResponseMsg) ->
    case backwater_http_signatures:validate_signed_msg_body(SignedResponseMsg, Body) of
        true ->
            decode_response_(StatusCode, CiHeaders, Body, Config, SignedResponseMsg);
        false ->
            {error, {{response_authentication, wrong_body_digest}, {status_code_name(StatusCode), Body}}}
    end.

-spec decode_response_(status_code(), headers(), binary(), backwater_client_config:t(),
                       backwater_http_signatures:signed_message()) -> response().
decode_response_(200 = StatusCode, CiHeaders, Body, Config, SignedResponseMsg) ->
    #{ rethrow_remote_exceptions := RethrowRemoteExceptions } = Config,
    StatusCodeName = status_code_name(StatusCode),
    RawResponseError = {StatusCodeName, Body},
    case decode_response_body(CiHeaders, Body, Config, SignedResponseMsg) of
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
decode_response_(StatusCode, CiHeaders, Body, Config, SignedResponseMsg) ->
    StatusCodeName = status_code_name(StatusCode),
    RawResponseError = {StatusCodeName, Body},
    case decode_response_body(CiHeaders, Body, Config, SignedResponseMsg) of
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

-spec decode_response_body(headers(), binary(), backwater_client_config:t(),
                           backwater_http_signatures:signed_message())
        -> {term, term()} |
           {raw, binary()} |
           {error, {invalid_content_type, binary()}} |
           {error, {undecodable_response_body, binary()}} |
           {error, {unknown_content_encoding, binary()}} |
           {error, {unknown_content_type, nonempty_binary()}}.
decode_response_body(CiHeaders, Body, Config, SignedResponseMsg) ->
    ContentEncodingLookup = find_content_encoding(CiHeaders, SignedResponseMsg),
    handle_response_body_content_encoding(
      ContentEncodingLookup, CiHeaders, Body, Config, SignedResponseMsg).

-spec status_code_name(status_code()) -> status_code_name().
status_code_name(400) -> bad_request;
status_code_name(401) -> unauthorized;
status_code_name(403) -> forbidden;
status_code_name(404) -> not_found;
status_code_name(406) -> not_acceptable;
status_code_name(413) -> payload_too_large;
status_code_name(415) -> unsupported_media_type;
status_code_name(500) -> internal_error;
status_code_name(Unknown) -> {http, Unknown}.

%% encoding

-spec handle_response_body_content_encoding({ok, binary()} | error,
                                            headers(), binary(), backwater_client_config:t(),
                                            backwater_http_signatures:signed_message())
        -> {term, term()} |
           {raw, binary()} |
           {error, {invalid_content_type, binary()}} |
           {error, {undecodable_response_body, binary()}} |
           {error, {unknown_content_encoding, binary()}} |
           {error, {unknown_content_type, nonempty_binary()}}.
handle_response_body_content_encoding({ok, <<"gzip">>}, CiHeaders, Body, Config, SignedResponseMsg) ->
    case backwater_encoding_gzip:decode(Body) of
        {ok, UncompressedBody} ->
            ContentTypeLookup = find_content_type(CiHeaders, SignedResponseMsg),
            handle_response_body_content_type(ContentTypeLookup, UncompressedBody, Config);
        {error, _Error} ->
            {error, {undecodable_response_body, Body}}
    end;
handle_response_body_content_encoding(Lookup, CiHeaders, Body, Config, SignedResponseMsg)
  when Lookup =:= error;
       Lookup =:= {ok, <<"identity">>} ->
    ContentTypeLookup = find_content_type(CiHeaders, SignedResponseMsg),
    handle_response_body_content_type(ContentTypeLookup, Body, Config);
handle_response_body_content_encoding({ok, OtherEncoding}, _CiHeaders, _Body, _Config, _SignedResponseMsg) ->
    {error, {unknown_content_encoding, OtherEncoding}}.

-spec find_content_encoding(headers(), backwater_http_signatures:signed_message())
        -> {ok, binary()} | error.
find_content_encoding(CiHeaders, SignedResponseMsg) ->
    find_header_value(?OPAQUE_BINARY(<<"content-encoding">>), CiHeaders, SignedResponseMsg).

%% content type

-spec handle_response_body_content_type({ok, {nonempty_binary(), [nonempty_binary()]}} |
                                        {error, {invalid_content_type, binary()}} |
                                        {error, content_type_missing},
                                        binary(), backwater_client_config:t())
        -> {term, term()} |
           {raw, binary()} |
           {error, {undecodable_response_body, binary()}} |
           {error, {unknown_content_type, nonempty_binary()}} |
           {error, {invalid_content_type, binary()}}.
handle_response_body_content_type({ok, {<<"application/x-erlang-etf">>, _Params}},
                                   Body, Config) ->
    #{ decode_unsafe_terms := DecodeUnsafeTerms } = Config,
    case backwater_media_etf:decode(Body, DecodeUnsafeTerms) of
        {ok, Decoded} -> {term, Decoded};
        error -> {error, {undecodable_response_body, Body}}
    end;
handle_response_body_content_type({ok, {OtherContentType, _Params}},
                                   _Body, _Config) ->
    {error, {unknown_content_type, OtherContentType}};
handle_response_body_content_type({error, {invalid_content_type, RawContentType}},
                                   _Body, _Config) ->
    {error, {invalid_content_type, RawContentType}};
handle_response_body_content_type({error, content_type_missing},
                                   Body, _Config) ->
    {raw, Body}.

-spec find_content_type(headers(), backwater_http_signatures:signed_message()) ->
            {ok, {nonempty_binary(), [nonempty_binary()]}} |
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

%-spec assert_header_safety(binary(), state()) -> true | no_return().
assert_header_safety(CiName, SignedResponseMsg) ->
    backwater_http_signatures:is_header_signed_in_signed_msg(CiName, SignedResponseMsg)
    orelse error({using_unsafe_header, CiName}).
