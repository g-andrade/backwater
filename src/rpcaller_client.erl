-module(rpcaller_client).

-include_lib("lhttpc/include/lhttpc.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([childspec/3]).
-export([start/2]).
-export([stop/1]).
-export([call/5]).
-export([call/6]).
-export([encode_http_request/5]).
-export([decode_http_response/5]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

childspec(Id, Ref, ClientConfig) ->
    rpcaller_client_sup:childspec(Id, Ref, ClientConfig).

start(Ref, ClientConfig) ->
    rpcaller_sup:start_client(Ref, ClientConfig).

stop(Ref) ->
    rpcaller_sup:stop_client(Ref).

call(Ref, Version, Module, Function, Args) ->
    call(Ref, Version, Module, Function, Args, #{}).

call(Ref, Version, Module, Function, Args, ConfigOverride) ->
    ClientConfig = rpcaller_client_config:get_config(Ref, ConfigOverride),
    #{ timeout := RequestTimeout } = ClientConfig,
    {RequestUrl, RequestMethod, RequestHeaders, RequestBody} =
        encode_http_request(Version, Module, Function, Args, ClientConfig),

    case lhttpc:request(RequestUrl, RequestMethod, RequestHeaders,
                        RequestBody, RequestTimeout)
    of
        {ok, {{Status, StatusMessage}, ResponseHeaders, ResponseBody}} ->
            decode_http_response(
              Status, StatusMessage, ResponseHeaders, ResponseBody, ClientConfig);
        {error, SocketError} ->
            {error, {socket, SocketError}}
    end.

encode_http_request(Version, Module, Function, Args, ClientConfig) ->
    Body = rpcaller_codec_etf:encode(Args),
    Arity = length(Args),
    Url = request_url(Version, Module, Function, Arity, ClientConfig),
    Method = "POST",
    MediaType = "application/x-erlang-etf",
    Headers =
        [{"accept", MediaType},
         {"content-length", integer_to_list(byte_size(Body))},
         {"content-type", MediaType}],
    encode_http_request_with_auth(Url, Method, Headers, Body, ClientConfig).

decode_http_response(Status, _StatusMessage, ResponseHeaders, ResponseBody, ClientConfig) when Status =:= 200 ->
    #{ rethrow_remote_exceptions := RethrowRemoteExceptions } = ClientConfig,
    case decode_response_body(ResponseHeaders, ResponseBody, ClientConfig) of
        {ok, {success, ReturnValue}} ->
            {ok, ReturnValue};
        {ok, {exception, Class, Exception, Stacktrace}} when RethrowRemoteExceptions ->
            erlang:raise(Class, Exception, Stacktrace);
        {ok, {exception, Class, Exception, Stacktrace}} ->
            {error, {remote_exception, Class, Exception, Stacktrace}};
        {error, _} = DecodeError ->
            DecodeError
    end;
decode_http_response(Status, _StatusMessage, _ResponseHeaders, _ResponseBody, _ClientConfig)
  when Status =:= 401 ->
    % TODO maybe look at headers
    {error, {rpcaller, unauthorized}};
decode_http_response(Status, StatusMessage, ResponseHeaders, ResponseBody, ClientConfig) ->
    case decode_response_body(ResponseHeaders, ResponseBody, ClientConfig) of
        {ok, {error, ReturnValue}} ->
            {error, ReturnValue};
        {error, response_content_type_missing} ->
            {error, {http, Status, StatusMessage, ResponseBody}};
        {error, _} = DecodeError ->
            DecodeError
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

request_url(Version, Module, Function, Arity, ClientConfig) ->
    #{ endpoint := Endpoint } = ClientConfig,
    string:join(
      [Endpoint,
       edoc_lib:escape_uri(Version),
       edoc_lib:escape_uri(atom_to_list(Module)),
       edoc_lib:escape_uri(atom_to_list(Function)),
       integer_to_list(Arity)],
      "/").

encode_http_request_with_auth(Url, Method, Headers, Body, #{ authentication := none }) ->
    {Url, Method, Headers, Body};
encode_http_request_with_auth(Url, Method, Headers, Body, ClientConfig) ->
    #{ authentication := {basic, {Username, Password}} } = ClientConfig,
    AuthHeader = {"authorization", http_basic_auth_header_value(Username, Password)},
    UpdatedHeaders = [AuthHeader | Headers],
    {Url, Method, UpdatedHeaders, Body}.

decode_response_body(ResponseHeaders, ResponseBody, ClientConfig) ->
    case find_content_type(ResponseHeaders) of
        {ok, {"application/x-erlang-etf", _Attributes}} ->
            #{ decode_unsafe_terms := DecodeUnsafeTerms } = ClientConfig,
            case rpcaller_codec_etf:decode(ResponseBody, DecodeUnsafeTerms) of
                {ok, Decoded} -> {ok, Decoded};
                error -> {error, {rpcaller, undecodable_response_body}}
            end;
        {error, invalid_content_type} ->
            {error, {rpcaller, invalid_response_content_type}};
        {error, content_type_missing} ->
            {error, {rpcaller, response_content_type_missing}}
    end.

find_content_type(Headers) ->
    case find_header_value("content-type", Headers) of
        {ok, ContentTypeStr} ->
            ContentTypeBin = unicode:characters_to_binary(ContentTypeStr),
            case binary:split(ContentTypeBin, [<<";">>, <<" ">>, <<$\n>>, <<$\r>>], [global, trim_all]) of
                [ActualBinContentType | BinAttributes] ->
                    {ok, {unicode:characters_to_list(ActualBinContentType),
                          [unicode:characters_to_list(V) || V <- BinAttributes]}};
                [] ->
                    {error, invalid_content_type}
            end;
        error ->
            {error, content_type_missing}
    end.

find_header_value(Key, Headers) ->
    LowerKey = string:to_lower(Key),
    Predicate = fun (HeaderName) -> string:to_lower(HeaderName) =:= LowerKey end,
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
    "basic " ++ base64:encode_to_string( iolist_to_binary([Username, ":", Password]) ).
