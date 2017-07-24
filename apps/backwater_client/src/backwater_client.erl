-module(backwater_client).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([child_spec/3]).
-export([start/2]).
-export([stop/1]).
-export([call/5]).
-export([call/6]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

child_spec(Id, Ref, ClientConfig) ->
    backwater_client_sup:child_spec(Id, Ref, ClientConfig).

start(Ref, ClientConfig) ->
    backwater_client_app_sup:start_client(Ref, ClientConfig).

stop(Ref) ->
    backwater_client_app_sup:stop_client(Ref).

call(Ref, Version, Module, Function, Args) ->
    call(Ref, Version, Module, Function, Args, #{}).

call(Ref, Version, Module, Function, Args, ConfigOverride) ->
    ClientConfig = backwater_client_config:get_config(Ref, ConfigOverride),
    #{ connect_timeout := ConnectTimeout,
       receive_timeout := ReceiveTimeout } = ClientConfig,
    {RequestMethod, RequestUrl, RequestHeaders, RequestBody} =
        backwater_client_http:encode_request(Version, Module, Function, Args, ClientConfig),

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
                    backwater_client_http:decode_response(StatusCode, ResponseHeaders, ResponseBody, ClientConfig);
                {error, BodyError} ->
                    backwater_error({response_body, BodyError})
            end;
        {error, SocketError} ->
            backwater_error({socket, SocketError})
    end.

% FIXME: duplicate in backwater_client_http, reconsider whole thing
backwater_error(Error) ->
    {error, Error}.
