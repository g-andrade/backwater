-module(backwater_client).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([child_spec/3]).                      -ignore_xref({child_spec,3}).
-export([start/2]).                           -ignore_xref({start,2}).
-export([stop/1]).                            -ignore_xref({stop,1}).
-export([call/5]).                            -ignore_xref({call,5}).
-export([call/6]).                            -ignore_xref({call,6}).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec child_spec(ChildId, Ref, Config) -> ChildSpec
        when ChildId :: term(),
             Ref :: atom(),
             Config :: backwater_client_config:t(),
             ChildSpec :: backwater_client_sup:child_spec(ChildId).

child_spec(ChildId, Ref, Config) ->
    backwater_client_sup:child_spec(ChildId, Ref, Config).


-spec start(Ref, Config) -> Result
        when Ref :: atom(),
             Config :: backwater_client_config:t(),
             Result :: backwater_sup_util:start_link_ret().

start(Ref, Config) ->
    backwater_sup:start_client(Ref, Config).


-spec stop(Ref) -> Result
        when Ref :: atom(),
             Result :: backwater_sup_util:stop_child_ret().

stop(Ref) ->
    backwater_sup:stop_client(Ref).


-spec call(Ref, Version, Module, Function, Args) -> Result
        when Ref :: atom(),
             Version :: unicode:chardata(),
             Module :: module(),
             Function :: atom(),
             Args :: [term()],
             Result :: backwater_client_http:response(OtherError),
             OtherError :: {response_body, atom() | {closed, binary()}} | {socket, term()}.

call(Ref, Version, Module, Function, Args) ->
    call(Ref, Version, Module, Function, Args, #{}).


-spec call(Ref, Version, Module, Function, Args, ConfigOverride) -> Result
        when Ref :: atom(),
             Version :: unicode:chardata(),
             Module :: module(),
             Function :: atom(),
             Args :: [term()],
             ConfigOverride :: backwater_client_config:override(),
             Result :: backwater_client_http:response(OtherError),
             OtherError :: {hackney, term()}.

call(Ref, Version, Module, Function, Args, ConfigOverride) ->
    Config = backwater_client_config:get_config(Ref, ConfigOverride),
    #{ connect_timeout := ConnectTimeout,
       receive_timeout := ReceiveTimeout } = Config,
    {{RequestMethod, RequestUrl, RequestHeaders, RequestBody}, RequestState} =
        backwater_client_http:encode_request(Version, Module, Function, Args, Config),

    Options =
        [{pool, default}, % TODO
         {connect_timeout, ConnectTimeout},
         {recv_timeout, ReceiveTimeout},
         with_body,
         {max_body, 1 bsl 20} % TODO
        ],

    case hackney:request(RequestMethod, RequestUrl, RequestHeaders, RequestBody, Options)
    of
        {ok, StatusCode, ResponseHeaders, ResponseBody} ->
            backwater_client_http:decode_response(StatusCode, ResponseHeaders, ResponseBody, RequestState);
        {error, Error} ->
            {error, {hackney, Error}}
    end.
