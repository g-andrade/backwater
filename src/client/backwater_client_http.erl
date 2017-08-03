-module(backwater_client_http).

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
        {bad_request, Body :: binary()} |
        {forbidden, Body :: binary()} |
        {http, status_code(), Body :: binary()} |
        {internal_error, Body :: binary()} |
        {invalid_content_type, status_code(), ContentType :: binary()} |
        {not_found, Body :: binary()} |
        {payload_too_large, Body :: binary()} |
        {unauthorized, Body :: binary()} |
        {undecodable_response_body, status_code(), Body :: binary()} |
        {unknown_content_encoding, status_code(), ContentEncoding :: binary()} |
        {unknown_content_type, status_code(), ContentType :: binary()} |
        {unsupported_media_type, Body :: binary()}.

-export_type([response_error/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec encode_request(Version, Module, Function, Args, Config) -> Request
            when Version :: unicode:chardata(),
                 Module :: module(),
                 Function :: atom(),
                 Args :: [term()],
                 Config :: backwater_client_config:t(),
                 Request :: request().

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


-spec decode_response(StatusCode, Headers, Body, Config) -> Response
            when StatusCode :: status_code(),
                 Headers :: headers(),
                 Body :: binary(),
                 Config :: backwater_client_config:t(),
                 Response :: response().

decode_response(StatusCode, Headers, Body, Config) ->
    CiHeaders = lists:keymap(fun backwater_util:latin1_binary_to_lower/1, 1, Headers),
    authenticate_response(StatusCode, CiHeaders, Body, Config).

%% ------------------------------------------------------------------
%% Internal Function Definitions - Requests
%% ------------------------------------------------------------------

-spec request_url(unicode:chardata(), module(), atom(), arity(),
                  backwater_client_config:t()) -> nonempty_binary().
request_url(Version, Module, Function, Arity, Config) ->
    #{ endpoint := Endpoint } = Config,
    iolist_to_binary(
      lists:join(
        "/",
        [Endpoint,
         edoc_lib:escape_uri(unicode:characters_to_list(Version)),
         edoc_lib:escape_uri(atom_to_list(Module)),
         edoc_lib:escape_uri(atom_to_list(Function)),
         integer_to_list(Arity)])).

-spec encode_request_with_compression(nonempty_binary(), nonempty_binary(),
                                      nonempty_headers(), binary(),
                                      backwater_client_config:t()) -> request().
encode_request_with_compression(Method, Url, Headers, Body, Config)
  when byte_size(Body) > ?COMPRESSION_THRESHOLD ->
    CompressedBody = backwater_encoding_gzip:encode(Body),
    UpdatedHeaders = [{<<"content-encoding">>, <<"gzip">>} | Headers],
    encode_request_with_auth(Method, Url, UpdatedHeaders, CompressedBody, Config);
encode_request_with_compression(Method, Url, Headers, Body, Config) ->
    encode_request_with_auth(Method, Url, Headers, Body, Config).

-spec encode_request_with_auth(nonempty_binary(), nonempty_binary(),
                               nonempty_headers(), binary(),
                               backwater_client_config:t()) -> request().
encode_request_with_auth(Method, Url, Headers1, Body, #{ authentication := {signature, Key} }) ->
    <<"http://localhost:8080", PathWithQs/binary>> = Url, % TODO
    SignaturesConfig = backwater_http_signatures:config(Key),
    SignaturesMsg = backwater_http_signatures:new_request_msg(Method, PathWithQs, Headers1),
    SignedMsg = backwater_http_signatures:sign_request(SignaturesConfig, SignaturesMsg, Body),
    Headers2 = backwater_http_signatures:list_real_msg_headers(SignedMsg),
    {Method, Url, Headers2, Body}.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Responses
%% ------------------------------------------------------------------

authenticate_response(StatusCode, CiHeaders, Body, Config) ->
    #{ authentication := {signature, Key} } = Config,
    SignaturesConfig = backwater_http_signatures:config(Key),
    SignedMsg = backwater_http_signatures:new_response_msg(StatusCode, {ci_headers, CiHeaders}),
    case backwater_http_signatures:validate_response_signature(SignaturesConfig, SignedMsg) of
        {ok, _SignedHeaderNames} ->
            % TODO deal with SignedHeaderNames
            authenticate_response_body(StatusCode, CiHeaders, Body, Config, SignedMsg);
        {error, Reason} ->
            {error, {Reason, StatusCode}}
    end.

authenticate_response_body(StatusCode, CiHeaders, Body, Config, SignedMsg) ->
    case backwater_http_signatures:validate_msg_body(SignedMsg, Body) of
        ok ->
            decode_response_(StatusCode, CiHeaders, Body, Config);
        {error, Reason} ->
            {error, {Reason, StatusCode}}
    end.

-spec decode_response_(status_code(), headers(), binary(), backwater_client_config:t()) -> response().
decode_response_(200 = StatusCode, CiHeaders, Body, Config) ->
    #{ rethrow_remote_exceptions := RethrowRemoteExceptions } = Config,
    case decode_response_body(CiHeaders, Body, Config) of
        {term, {success, ReturnValue}} ->
            {ok, ReturnValue};
        {term, {exception, Class, Exception, Stacktrace}} when RethrowRemoteExceptions ->
            erlang:raise(Class, Exception, Stacktrace);
        {term, {exception, Class, Exception, Stacktrace}} ->
            {error, {remote_exception, Class, Exception, Stacktrace}};
        {raw, Binary} ->
            {error, {http, StatusCode, Binary}};
        {error, {unknown_content_encoding, ContentEncoding}} ->
            {error, {unknown_content_encoding, StatusCode, ContentEncoding}};
        {error, {undecodable_response_body, Binary}} ->
            {error, {undecodable_response_body, StatusCode, Binary}};
        {error, {unknown_content_type, RawContentType}} ->
            {error, {unknown_content_type, StatusCode, RawContentType}};
        {error, {invalid_content_type, RawContentType}} ->
            {error, {invalid_content_type, StatusCode, RawContentType}}
    end;
decode_response_(StatusCode, CiHeaders, Body, Config) ->
    case decode_response_body(CiHeaders, Body, Config) of
        {term, Error} ->
            {error, Error};
        {raw, Binary} when StatusCode =:= 400 ->
            {error, {bad_request, Binary}};
        {raw, Binary} when StatusCode =:= 401 ->
            {error, {unauthorized, Binary}};
        {raw, Binary} when StatusCode =:= 403 ->
            {error, {forbidden, Binary}};
        {raw, Binary} when StatusCode =:= 404 ->
            {error, {not_found, Binary}};
        {raw, Binary} when StatusCode =:= 406 ->
            {error, {not_acceptable, Binary}};
        {raw, Binary} when StatusCode =:= 413 ->
            {error, {payload_too_large, Binary}};
        {raw, Binary} when StatusCode =:= 415 ->
            {error, {unsupported_media_type, Binary}};
        {raw, Binary} when StatusCode =:= 500 ->
            {error, {internal_error, Binary}};
        {raw, Binary} ->
            {error, {http, StatusCode, Binary}};
        {error, {unknown_content_encoding, ContentEncoding}} ->
            {error, {unknown_content_encoding, StatusCode, ContentEncoding}};
        {error, {undecodable_response_body, Binary}} ->
            {error, {undecodable_response_body, StatusCode, Binary}};
        {error, {unknown_content_type, RawContentType}} ->
            {error, {unknown_content_type, StatusCode, RawContentType}};
        {error, {invalid_content_type, RawContentType}} ->
            {error, {invalid_content_type, StatusCode, RawContentType}}
    end.

-spec decode_response_body(headers(), binary(), backwater_client_config:t())
        -> {term, term()} |
           {raw, binary()} |
           {error, {invalid_content_type, binary()}} |
           {error, {undecodable_response_body, binary()}} |
           {error, {unknown_content_encoding, binary()}} |
           {error, {unknown_content_type, nonempty_binary()}}.
decode_response_body(CiHeaders, Body, Config) ->
    ContentEncodingLookup = find_content_encoding(CiHeaders),
    handle_response_body_content_encoding(
      ContentEncodingLookup, CiHeaders, Body, Config).

%% encoding

-spec handle_response_body_content_encoding({ok, binary()} | error,
                                            headers(), binary(), backwater_client_config:t())
        -> {term, term()} |
           {raw, binary()} |
           {error, {invalid_content_type, binary()}} |
           {error, {undecodable_response_body, binary()}} |
           {error, {unknown_content_encoding, binary()}} |
           {error, {unknown_content_type, nonempty_binary()}}.
handle_response_body_content_encoding({ok, <<"gzip">>}, CiHeaders, Body, Config) ->
    case backwater_encoding_gzip:decode(Body) of
        {ok, UncompressedBody} ->
            ContentTypeLookup = find_content_type(CiHeaders),
            handle_response_body_content_type(ContentTypeLookup, UncompressedBody, Config);
        {error, _Error} ->
            {error, {undecodable_response_body, Body}}
    end;
handle_response_body_content_encoding(Lookup, CiHeaders, Body, Config)
  when Lookup =:= error;
       Lookup =:= {ok, <<"identity">>} ->
    ContentTypeLookup = find_content_type(CiHeaders),
    handle_response_body_content_type(ContentTypeLookup, Body, Config);
handle_response_body_content_encoding({ok, OtherEncoding}, _CiHeaders, _Body, _Config) ->
    {error, {unknown_content_encoding, OtherEncoding}}.

-spec find_content_encoding(headers()) -> {ok, binary()} | error.
find_content_encoding(CiHeaders) ->
    find_header_value(?OPAQUE_BINARY(<<"content-encoding">>), CiHeaders).

%% content type

-spec handle_response_body_content_type({ok, {nonempty_binary(), [nonempty_binary()]}} |
                                        {error, {invalid_content_type, binary()}} |
                                        {error, content_type_missing},
                                        binary(), backwater_client_config:t())
        -> {term, term()} |
           {raw, binary()} |
           {error, {undecodable_response_body, binary()}} |
           {error, {unknown_content_type, binary()}} |
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

-spec find_content_type(headers()) ->
            {ok, {nonempty_binary(), [nonempty_binary()]}} |
            {error, {invalid_content_type, binary()}} |
            {error, content_type_missing}.
find_content_type(CiHeaders) ->
    case find_header_value(?OPAQUE_BINARY(<<"content-type">>), CiHeaders) of
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

-spec find_header_value(nonempty_binary(), headers()) -> {ok, binary()} | error.
find_header_value(CiKey, CiHeaders) ->
    case lists:keyfind(CiKey, 1, CiHeaders) of
        {CiKey, Value} -> {ok, Value};
        false -> error
    end.
