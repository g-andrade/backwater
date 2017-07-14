-module(backwater_http).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([encode_request/5]).
-export([decode_response/4]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

encode_request(Version, Module, Function, Args, ClientConfig) ->
    Body = backwater_media_etf:encode(Args),
    Arity = length(Args),
    Method = <<"POST">>,
    Url = request_url(Version, Module, Function, Arity, ClientConfig),
    MediaType = <<"application/x-erlang-etf">>,
    Headers =
        [{<<"accept">>, <<MediaType/binary>>},
         {<<"accept-encoding">>, <<"gzip">>},
         {<<"content-type">>, <<MediaType/binary>>}],
    encode_request_with_auth(Method, Url, Headers, Body, ClientConfig).

decode_response(StatusCode, Headers, Body, ClientConfig) ->
    CiHeaders = lists:keymap(fun latin1_binary_to_lower/1, 1, Headers),
    decode_response_(StatusCode, CiHeaders, Body, ClientConfig).

%% ------------------------------------------------------------------
%% Internal Function Definitions - Requests
%% ------------------------------------------------------------------

request_url(Version, Module, Function, Arity, ClientConfig) ->
    #{ endpoint := Endpoint } = ClientConfig,
    iolist_to_binary(
      lists:join(
        "/",
        [Endpoint,
         edoc_lib:escape_uri(Version),
         edoc_lib:escape_uri(atom_to_list(Module)),
         edoc_lib:escape_uri(atom_to_list(Function)),
         integer_to_list(Arity)])).

encode_request_with_auth(Method, Url, Headers, Body, #{ authentication := none }) ->
    {Method, Url, Headers, Body};
encode_request_with_auth(Method, Url, Headers, Body, ClientConfig) ->
    #{ authentication := {basic, {Username, Password}} } = ClientConfig,
    AuthHeader = {"authorization", http_basic_auth_header_value(Username, Password)},
    UpdatedHeaders = [AuthHeader | Headers],
    {Method, Url, UpdatedHeaders, Body}.

http_basic_auth_header_value(Username, Password) ->
    <<"basic ", (base64:encode( iolist_to_binary([Username, ":", Password]) ))/binary>>.

%% ------------------------------------------------------------------
%% Internal Function Definitions - Responses
%% ------------------------------------------------------------------

decode_response_(200 = StatusCode, CiHeaders, Body, ClientConfig) ->
    #{ rethrow_remote_exceptions := RethrowRemoteExceptions } = ClientConfig,
    case decode_response_body(CiHeaders, Body, ClientConfig) of
        {term, {success, ReturnValue}} ->
            {ok, ReturnValue};
        {term, {exception, Class, Exception, Stacktrace}} when RethrowRemoteExceptions ->
            erlang:raise(Class, Exception, Stacktrace);
        {term, {exception, Class, Exception, Stacktrace}} ->
            backwater_error({remote_exception, Class, Exception, Stacktrace});
        {raw, Binary} ->
            backwater_error({http, StatusCode, Binary});
        {error, {unknown_content_encoding, ContentEncoding}} ->
            backwater_error({unknown_content_encoding, ContentEncoding});
        {error, {undecodable_response_body, Binary}} ->
            backwater_error({undecodable_response_body, StatusCode, Binary});
        {error, {invalid_content_type, RawContentType}} ->
            backwater_error({invalid_content_type, StatusCode, RawContentType})
    end;
decode_response_(StatusCode, CiHeaders, Body, ClientConfig) ->
    case decode_response_body(CiHeaders, Body, ClientConfig) of
        {term, Error} ->
            backwater_error(Error);
        {raw, Binary} when StatusCode =:= 400 ->
            backwater_error({bad_request, Binary});
        {raw, Binary} when StatusCode =:= 401 ->
            backwater_error({unauthorized, Binary});
        {raw, Binary} when StatusCode =:= 403 ->
            backwater_error({forbidden, Binary});
        {raw, Binary} when StatusCode =:= 404 ->
            backwater_error({not_found, Binary});
        {raw, Binary} when StatusCode =:= 406 ->
            backwater_error({not_acceptable, Binary});
        {raw, Binary} when StatusCode =:= 413 ->
            backwater_error({payload_too_large, Binary});
        {raw, Binary} when StatusCode =:= 415 ->
            backwater_error({unsupported_media_type, Binary});
        {raw, Binary} when StatusCode =:= 500 ->
            backwater_error({internal_error, Binary});
        {raw, Binary} ->
            backwater_error({http, StatusCode, Binary});
        {error, {unknown_content_encoding, ContentEncoding}} ->
            backwater_error({unknown_content_encoding, ContentEncoding});
        {error, {undecodable_response_body, Binary}} ->
            backwater_error({undecodable_response_body, StatusCode, Binary});
        {error, {invalid_content_type, RawContentType}} ->
            backwater_error({invalid_content_type, StatusCode, RawContentType})
    end.

decode_response_body(CiHeaders, Body, ClientConfig) ->
    ContentEncodingLookup = find_content_encoding(CiHeaders),
    handle_response_body_content_encoding(
      ContentEncodingLookup, CiHeaders, Body, ClientConfig).

%% encoding

handle_response_body_content_encoding({ok, <<"gzip">>}, CiHeaders, Body, ClientConfig) ->
    case backwater_encoding_gzip:decode(Body) of
        {ok, UncompressedBody} ->
            ContentTypeLookup = find_content_type(CiHeaders),
            handle_response_body_content_type(ContentTypeLookup, UncompressedBody, ClientConfig);
        {error, _Error} ->
            {error, {undecodable_response_body, Body}}
    end;
handle_response_body_content_encoding({ok, OtherEncoding}, _CiHeaders, _Body, _ClientConfig) ->
    {error, {unknown_content_encoding, OtherEncoding}};
handle_response_body_content_encoding(error, CiHeaders, Body, ClientConfig) ->
    ContentTypeLookup = find_content_type(CiHeaders),
    handle_response_body_content_type(ContentTypeLookup, Body, ClientConfig).

find_content_encoding(CiHeaders) ->
    find_header_value(<<"content-encoding">>, CiHeaders).

%% content type

handle_response_body_content_type({ok, {<<"application/x-erlang-etf">>, _Params}},
                                   Body, ClientConfig) ->
    #{ decode_unsafe_terms := DecodeUnsafeTerms } = ClientConfig,
    case backwater_media_etf:decode(Body, DecodeUnsafeTerms) of
        {ok, Decoded} -> {term, Decoded};
        error -> {error, {undecodable_response_body, Body}}
    end;
handle_response_body_content_type({error, {invalid_content_type, RawContentType}},
                                   _Body, _ClientConfig) ->
    {error, {invalid_content_type, RawContentType}};
handle_response_body_content_type({error, content_type_missing},
                                   Body, _ClientConfig) ->
    {raw, Body}.

find_content_type(CiHeaders) ->
    case find_header_value(<<"content-type">>, CiHeaders) of
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

find_header_value(CiKey, CiHeaders) ->
    case lists:keyfind(CiKey, 1, CiHeaders) of
        {CiKey, Value} -> {ok, Value};
        false -> error
    end.

latin1_binary_to_lower(Bin) ->
    % TODO: optimize
    list_to_binary( string:to_lower( binary_to_list(Bin) ) ).

% FIXME: duplicate in backwater_client, reconsider whole thing
backwater_error(Error) ->
    {error, Error}.
