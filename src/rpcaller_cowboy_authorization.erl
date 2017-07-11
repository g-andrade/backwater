-module(rpcaller_cowboy_authorization).
-export([verify_req/2]).
-export([sign_resp/4]).

% TODO actually include required headers
-define(REJECTION_HEADER_VALUE, <<"signature realm=\"rpcaller\",headers=\"(request-target) date\"">>).

verify_req(RPCallerOpts, Req) ->
    {BinMethod, Req2} = cowboy_req:method(Req),
    {BinHostlessURI, Req3} = cowboy_req_hostless_uri(Req2),
    {BinHeaders, Req4} = cowboy_req:headers(Req3),
    Method = binary_to_list(BinMethod),
    HostlessURI = binary_to_list(BinHostlessURI),
    Headers = string_headers(BinHeaders),
    handle_decode_authorized_request_result(
      rpcaller_http_signatures:decode_authorized_request(Method, HostlessURI, Headers),
      RPCallerOpts,
      Req4).


sign_resp(RPCallerOpts, RequestAuthorization, Body, Req) ->
    #{ key_id := KeyId } = RequestAuthorization,
    #{ authenticated_access := AuthenticatedAccessConfs } = RPCallerOpts,
    #{ signing := SigningParams } = maps:get(KeyId, AuthenticatedAccessConfs),

    % XXX very, very dirty hack.
    % pre versions of cowboy 2.0.0 show that we'll get an interface for this,
    % but not yet..
    BinHeaders = cowboy_req:get(resp_headers, Req),

    % some more headers we need to sign
    UpdatedBinHeaders =
        rpcaller_util:kvlists_merge(
          [{<<"date">>, cowboy_clock:rfc1123()},
           {<<"content-length">>, integer_to_binary(byte_size(Body))}],
          BinHeaders),

    Headers = string_headers(UpdatedBinHeaders),
    AuthorizedResponse =
        rpcaller_http_signatures:create_authorized_response(KeyId, SigningParams, Headers, Body),
    HeadersAfterAuthorization  =
        rpcaller_http_signatures:encode_authorized_response_headers(AuthorizedResponse),

    lists:foldl(
      fun ({Name, Value} = Header, ReqAcc) ->
              case lists:member(Header, Headers) of
                  true -> ReqAcc;
                  false ->
                      BinName = list_to_binary(Name),
                      BinValue = list_to_binary(Value),
                      cowboy_req:set_resp_header(BinName, BinValue, ReqAcc)
              end
      end,
      Req,
      HeadersAfterAuthorization).


handle_decode_authorized_request_result({ok, AuthorizedRequest},
                                        #{ authenticated_access := AuthenticatedAccessConfs }, Req) ->
    #{ authorization := #{ key_id := KeyId } } = AuthorizedRequest,
    case maps:find(KeyId, AuthenticatedAccessConfs) of
        {ok, BaseAccessConf} ->
            verify_authorized_request(AuthorizedRequest, BaseAccessConf, Req);
        error ->
            {{false, ?REJECTION_HEADER_VALUE}, Req}
    end;
handle_decode_authorized_request_result({ok, _AuthorizedRequest},
                                        #{ unauthenticated_access := BaseAccessConf }, Req) ->
    AccessConfDefaults =
        #{ decode_unsafe_terms => false,
           exposed_modules => [],
           return_exception_stacktraces => false },
    AccessConf =
        maps:merge(AccessConfDefaults, BaseAccessConf),
    {{true, AccessConf}, Req};
handle_decode_authorized_request_result({error, authorization_header_missing},
                                        #{ unauthenticated_access := BaseAccessConf }, Req) ->
    % TODO remove repeated code (previous function definition)
    AccessConfDefaults =
        #{ decode_unsafe_terms => false,
           exposed_modules => [],
           return_exception_stacktraces => false },
    AccessConf =
        maps:merge(AccessConfDefaults, BaseAccessConf),
    {{true, AccessConf}, Req};
handle_decode_authorized_request_result({error, _DecodingError},
                                        _RPCallerOpts, Req) ->
    % TODO feedback of error?
    {{false, ?REJECTION_HEADER_VALUE}, Req}.


verify_authorized_request(AuthorizedRequest, BaseAccessConf, Req) ->
    #{ signing := SigningParams } = BaseAccessConf,
    case rpcaller_http_signatures:verify_authorized_request(AuthorizedRequest, SigningParams) of
        {true, BodyDigest} ->
            #{ authorization := Authorization } = AuthorizedRequest,
            AccessConfDefaults =
                #{ decode_unsafe_terms => true,
                   exposed_modules => [],
                   return_exception_stacktraces => true },
            AccessConf =
                maps:merge(AccessConfDefaults, BaseAccessConf),
            {{true, AccessConf, Authorization, BodyDigest}, Req};
        false ->
            {{false, ?REJECTION_HEADER_VALUE}, Req}
    end.


string_headers(BinHeaders) ->
    lists:map(
      fun ({NameBin, ValueBin}) ->
              {rpcaller_util:iolist_to_list(NameBin), rpcaller_util:iolist_to_list(ValueBin)}
      end,
      BinHeaders).

cowboy_req_hostless_uri(Req) ->
    {Path, Req2} = cowboy_req:path(Req),
    {QueryString, Req3} = cowboy_req:qs(Req2),
    case QueryString of
        <<>> -> {Path, Req3};
        <<_/binary>> -> {<<Path/binary, "?", QueryString/binary>>, Req3}
    end.
