-module(backwater_client).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([childspec/3]).
-export([start/2]).
-export([stop/1]).
-export([call/5]).
-export([call/6]).
-export([encode_http_request/5]).
-export([decode_http_response/4]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

childspec(Id, Ref, ClientConfig) ->
    backwater_client_sup:childspec(Id, Ref, ClientConfig).

start(Ref, ClientConfig) ->
    backwater_sup:start_client(Ref, ClientConfig).

stop(Ref) ->
    backwater_sup:stop_client(Ref).

call(Ref, Version, Module, Function, Args) ->
    call(Ref, Version, Module, Function, Args, #{}).

call(Ref, Version, Module, Function, Args, ConfigOverride) ->
    ClientConfig = backwater_client_config:get_config(Ref, ConfigOverride),
    #{ connect_timeout := ConnectTimeout,
       receive_timeout := ReceiveTimeout } = ClientConfig,
    {RequestMethod, RequestUrl, RequestHeaders, RequestBody} =
        encode_http_request(Version, Module, Function, Args, ClientConfig),

    Options =
        [{pool, default}, % TODO
         {connect_timeout, ConnectTimeout},
         {recv_timeout, ReceiveTimeout}],

    case hackney:request(RequestMethod, RequestUrl, RequestHeaders,
                         RequestBody, Options)
    of
        {ok, StatusCode, ResponseHeaders, ClientRef} ->
            case hackney:body(ClientRef) of
                {ok, ResponseBody} ->
                    decode_http_response(
                      StatusCode, ResponseHeaders, ResponseBody, ClientConfig);
                {error, BodyError} ->
                    {error, {body, BodyError}}
            end;
        {error, SocketError} ->
            {error, {socket, SocketError}}
    end.

encode_http_request(Version, Module, Function, Args, ClientConfig) ->
    Body = backwater_codec_etf:encode(Args),
    Arity = length(Args),
    Method = "POST",
    Url = request_url(Version, Module, Function, Arity, ClientConfig),
    MediaType = <<"application/x-erlang-etf">>,
    Headers =
        [{<<"accept">>, MediaType},
         {<<"content-type">>, MediaType}],
    encode_http_request_with_auth(Method, Url, Headers, Body, ClientConfig).

decode_http_response(StatusCode, ResponseHeaders, ResponseBody, ClientConfig) when StatusCode =:= 200 ->
    #{ rethrow_remote_exceptions := RethrowRemoteExceptions } = ClientConfig,
    case decode_response_body(ResponseHeaders, ResponseBody, ClientConfig) of
        {term, {success, ReturnValue}} ->
            {ok, ReturnValue};
        {term, {exception, Class, Exception, Stacktrace}} when RethrowRemoteExceptions ->
            erlang:raise(Class, Exception, Stacktrace);
        {term, {exception, Class, Exception, Stacktrace}} ->
            {error, {remote_exception, Class, Exception, Stacktrace}};
        {raw, Binary} ->
            {error, {raw, StatusCode, Binary}};
        {error, {undecodable_response_body, Binary}} ->
            {error, {undecodable_response_body, StatusCode, Binary}};
        {error, {invalid_content_type, RawContentType}} ->
            {error, {invalid_content_type, StatusCode, RawContentType}}
    end;
decode_http_response(StatusCode, _ResponseHeaders, _ResponseBody, _ClientConfig)
  when StatusCode =:= 401 ->
    % TODO maybe look at headers
    {error, {backwater, unauthorized}};
decode_http_response(StatusCode, ResponseHeaders, ResponseBody, ClientConfig) ->
    case decode_response_body(ResponseHeaders, ResponseBody, ClientConfig) of
        {term, {error, ReturnValue}} ->
            {error, ReturnValue};
        {term, <<Raw/binary>>} ->
            {error, Raw};
        {raw, Binary} ->
            {error, {raw, StatusCode, Binary}};
        {error, response_content_type_missing} ->
            {error, {http, StatusCode, ResponseBody}};
        {error, {undecodable_response_body, Binary}} ->
            {error, {undecodable_response_body, StatusCode, Binary}};
        {error, {invalid_content_type, RawContentType}} ->
            {error, {invalid_content_type, StatusCode, RawContentType}}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions
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

encode_http_request_with_auth(Method, Url, Headers, Body, #{ authentication := none }) ->
    {Method, Url, Headers, Body};
encode_http_request_with_auth(Method, Url, Headers, Body, ClientConfig) ->
    #{ authentication := {basic, {Username, Password}} } = ClientConfig,
    AuthHeader = {"authorization", http_basic_auth_header_value(Username, Password)},
    UpdatedHeaders = [AuthHeader | Headers],
    {Method, Url, UpdatedHeaders, Body}.

decode_response_body(ResponseHeaders, ResponseBody, ClientConfig) ->
    case find_content_type(ResponseHeaders) of
        {ok, {<<"application/x-erlang-etf">>, _Attributes}} ->
            #{ decode_unsafe_terms := DecodeUnsafeTerms } = ClientConfig,
            case backwater_codec_etf:decode(ResponseBody, DecodeUnsafeTerms) of
                {ok, Decoded} -> {term, Decoded};
                error -> {error, {undecodable_response_body, ResponseBody}}
            end;
        {error, {invalid_content_type, RawContentType}} ->
            {error, {invalid_response_content_type, RawContentType}};
        {error, content_type_missing} ->
            {raw, ResponseBody}
    end.

find_content_type(Headers) ->
    case find_header_value(<<"content-type">>, Headers) of
        {ok, ContentTypeStr} ->
            ContentTypeBin = unicode:characters_to_binary(ContentTypeStr),
            case binary:split(ContentTypeBin, [<<";">>, <<" ">>, <<$\n>>, <<$\r>>], [global, trim_all]) of
                [ActualBinContentType | BinAttributes] ->
                    {ok, {ActualBinContentType, [V || V <- BinAttributes]}};
                [] ->
                    {error, {invalid_content_type, ContentTypeBin}}
            end;
        error ->
            {error, content_type_missing}
    end.

find_header_value(Key, Headers) ->
    LowerKey = backwater_util:latin1_binary_to_lower(Key),
    Predicate = fun (HeaderName) -> backwater_util:latin1_binary_to_lower(HeaderName) =:= LowerKey end,
    case lists_keyfind_predicate(Predicate, 1, Headers) of
        {_HeaderName, HeaderValue} -> {ok, HeaderValue};
        false -> error
    end.

lists_keyfind_predicate(Predicate, N, [H|T]) ->
    Element = element(N, H),
    case Predicate(Element) of
        true -> H;
        false -> lists_keyfind_predicate(Predicate, N, T)
    end;
lists_keyfind_predicate(_Predicate, _N, []) ->
    false.

http_basic_auth_header_value(Username, Password) ->
    <<"basic ", (base64:encode( iolist_to_binary([Username, ":", Password]) ))/binary>>.
