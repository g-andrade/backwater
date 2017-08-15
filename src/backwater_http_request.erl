-module(backwater_http_request).

-include_lib("hackney/include/hackney_lib.hrl").
-include("backwater_client.hrl").
-include("backwater_common.hrl").
-include("backwater_http_api.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([encode/5]).

%% ------------------------------------------------------------------
%% Common Test Helper Exports
%% ------------------------------------------------------------------

-ifdef(TEST).
-export(['_encode'/6]).
-endif.

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(REQUEST_ID_SIZE, 16).        % in bytes; before being encoded using base64

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type nonempty_headers() :: [{nonempty_binary(), binary()}, ...].
-export_type([nonempty_headers/0]).

-type state() :: #{ signed_request_msg := backwater_http_signatures:signed_message() }.
-export_type([state/0]).

-type t() :: {Method :: nonempty_binary(), Url :: nonempty_binary(),
              Headers :: nonempty_headers(), Body :: binary()}.
-export_type([t/0]).

-type stateful_request() :: {t(), state()}.

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec encode(Endpoint, Module, Function, Args, Secret) -> {Request, RequestState}
            when Endpoint :: nonempty_binary(),
                 Module :: module(),
                 Function :: atom(),
                 Args :: [term()],
                 Secret :: binary(),
                 Request :: t(),
                 RequestState :: state().

encode(Endpoint, Module, Function, Args, Secret) ->
    Body = backwater_media_etf:encode(Args),
    Arity = length(Args),
    Method = ?OPAQUE_BINARY(<<"POST">>),
    Url = request_url(Endpoint, Module, Function, Arity),
    MediaType = ?OPAQUE_BINARY(<<"application/x-erlang-etf">>),
    Headers =
        [{?OPAQUE_BINARY(<<"accept">>), ?OPAQUE_BINARY(<<MediaType/binary>>)},
         {?OPAQUE_BINARY(<<"accept-encoding">>), ?OPAQUE_BINARY(<<"gzip">>)},
         {?OPAQUE_BINARY(<<"content-type">>), ?OPAQUE_BINARY(<<MediaType/binary>>)}],
    compress(Method, Url, Headers, Body, Secret).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-spec request_url(nonempty_binary(), module(), atom(), arity())
        -> nonempty_binary().
request_url(Endpoint, Module, Function, Arity) ->
    PathComponents =
        [iolist_to_binary(?BACKWATER_HTTP_API_BASE_ENDPOINT),
         iolist_to_binary(?BACKWATER_HTTP_API_VERSION),
         hackney_url:urlencode(atom_to_binary(Module, utf8)),
         hackney_url:urlencode(atom_to_binary(Function, utf8)),
         integer_to_binary(Arity)],
    QueryString = <<>>,
    hackney_url:make_url(Endpoint, PathComponents, QueryString).

-spec compress(nonempty_binary(), nonempty_binary(), nonempty_headers(), binary(), binary())
        -> stateful_request().
compress(Method, Url, Headers, Body, Secret) when byte_size(Body) > ?REQUEST_COMPRESSION_THRESHOLD ->
    CompressedBody = backwater_encoding_gzip:encode(Body),
    UpdatedHeaders = [{<<"content-encoding">>, <<"gzip">>} | Headers],
    authenticate(Method, Url, UpdatedHeaders, CompressedBody, Secret);
compress(Method, Url, Headers, Body, Secret) ->
    authenticate(Method, Url, Headers, Body, Secret).

-spec authenticate(nonempty_binary(), nonempty_binary(), nonempty_headers(), binary(), binary())
        -> stateful_request().
authenticate(Method, Url, Headers1, Body, Secret) ->
    EncodedPathWithQs = url_encoded_path_with_qs(Url),
    SignaturesConfig = backwater_http_signatures:config(Secret),
    RequestMsg = backwater_http_signatures:new_request_msg(Method, EncodedPathWithQs, Headers1),
    RequestId = base64:encode( crypto:strong_rand_bytes(?REQUEST_ID_SIZE) ),
    SignedRequestMsg = backwater_http_signatures:sign_request(SignaturesConfig, RequestMsg, Body, RequestId),
    Headers2 = backwater_http_signatures:list_real_msg_headers(SignedRequestMsg),
    Request = {?OPAQUE_BINARY(Method), ?OPAQUE_BINARY(Url), Headers2, Body},
    State = #{ signed_request_msg => SignedRequestMsg },
    {Request, State}.

-spec url_encoded_path_with_qs(nonempty_binary()) -> binary().
url_encoded_path_with_qs(Url) ->
    HackneyUrl = hackney_url:parse_url(Url),
    #hackney_url{ path = Path, qs = QueryString } = HackneyUrl,
    EncodedPath  = hackney_url:pathencode(Path),
    <<EncodedPath/binary, QueryString/binary>>.

%% ------------------------------------------------------------------
%% Common Test Helper Definitions
%% ------------------------------------------------------------------

-ifdef(TEST).
%% @private
'_encode'(Endpoint, Module, Function, Args, Secret, Override) ->
    UpdateArityWith = maps:get(update_arity_with, Override, fun identity/1),
    UpdateUrlWith = maps:get(update_url_with, Override, fun identity/1),
    UpdateMethodWith = maps:get(update_method_with, Override, fun identity/1),
    UpdateHeadersWith = maps:get({update_headers_with, before_compression}, Override, fun identity/1),
    UpdateBodyWith = maps:get({update_body_with, before_compression}, Override, fun identity/1),

    Arity = UpdateArityWith(length(Args)),
    Method1 = UpdateMethodWith(<<"POST">>),
    Url1 = UpdateUrlWith(request_url(Endpoint, Module, Function, Arity)),
    MediaType = <<"application/x-erlang-etf">>,
    Headers1 = UpdateHeadersWith(
                 [{<<"accept">>, <<MediaType/binary>>},
                  {<<"accept-encoding">>, <<"gzip">>},
                  {<<"content-type">>, <<MediaType/binary>>}]),
    Body1 = UpdateBodyWith(backwater_media_etf:encode(Args)),

    '_compress'(Method1, Url1, Headers1, Body1, Secret, Override).

'_compress'(Method, Url, Headers1, Body1, Secret, Override)
   when byte_size(Body1) > ?REQUEST_COMPRESSION_THRESHOLD ->
    UpdateHeadersWith = maps:get({update_headers_with, before_authentication}, Override, fun identity/1),
    UpdateBodyWith = maps:get({update_body_with, before_authentication}, Override, fun identity/1),
    Headers2 = UpdateHeadersWith([{<<"content-encoding">>, <<"gzip">>} | Headers1]),
    Body2 = UpdateBodyWith(backwater_encoding_gzip:encode(Body1)),
    '_authenticate'(Method, Url, Headers2, Body2, Secret, Override);
'_compress'(Method, Url, Headers1, Body1, Secret, Override) ->
    UpdateHeadersWith = maps:get({update_headers_with, before_authentication}, Override, fun identity/1),
    UpdateBodyWith = maps:get({update_body_with, before_authentication}, Override, fun identity/1),
    Headers2 = UpdateHeadersWith(Headers1),
    Body2 = UpdateBodyWith(Body1),
    '_authenticate'(Method, Url, Headers2, Body2, Secret, Override).

'_authenticate'(Method, Url, Headers1, Body1, Secret, Override) ->
    UpdateHeadersWith = maps:get({update_headers_with, final}, Override, fun identity/1),
    UpdateBodyWith = maps:get({update_body_with, final}, Override, fun identity/1),

    EncodedPathWithQs = url_encoded_path_with_qs(Url),
    SignaturesConfig = backwater_http_signatures:config(Secret),
    RequestMsg = backwater_http_signatures:new_request_msg(Method, EncodedPathWithQs, Headers1),
    RequestId = base64:encode( crypto:strong_rand_bytes(?REQUEST_ID_SIZE) ),
    SignedRequestMsg = backwater_http_signatures:sign_request(SignaturesConfig, RequestMsg, Body1, RequestId),
    Headers2 = backwater_http_signatures:list_real_msg_headers(SignedRequestMsg),

    Headers3 = UpdateHeadersWith(Headers2),
    Body2 = UpdateBodyWith(Body1),
    Request = {Method, Url, Headers3, Body2},
    State = #{ signed_request_msg => SignedRequestMsg },
    {Request, State}.

identity(V) -> V.
-endif.
