-module(backwater_client_config).
-behaviour(gen_server).

-include("../backwater_common.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/2]). -ignore_xref({start_link, 2}).
-export([child_spec/3]).
-export([get_config/2]).

%% ------------------------------------------------------------------
%% gen_server Function Exports
%% ------------------------------------------------------------------

-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(CB_MODULE, ?MODULE).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type child_spec() ::
        #{ id := term(),
           start := {?MODULE, start_link, [term() | t(), ...]},
           restart := permanent,
           type := worker,
           modules := [?MODULE, ...] }.

-export_type([child_spec/0]).

-type t() ::
        #{ endpoint := nonempty_binary(),
           authentication := authentication(),
           connect_timeout => timeout(),
           receive_timeout => timeout(),
           decode_unsafe_terms => boolean(),
           rethrow_remote_exceptions => boolean() }.

-export_type([t/0]).

-type override() ::
        #{ endpoint => nonempty_binary(),
           authentication => authentication(),
           connect_timeout => timeout(),
           receive_timeout => timeout(),
           decode_unsafe_terms => boolean(),
           rethrow_remote_exceptions => boolean() }.

-export_type([override/0]).

-type authentication() :: {signature, Key :: binary()}.

-export_type([authentication/0]).

-type state() :: no_state.

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec start_link(term(), t()) -> {ok, pid()} | ignore | {error, term()}.
%% @private
start_link(Ref, Config) ->
    gen_server:start_link({local, server_name(Ref)}, ?CB_MODULE, [Ref, Config], []).

-spec child_spec(term(), term(), t()) -> child_spec().
%% @private
child_spec(Id, Ref, Config) ->
    #{ id => Id,
       start => {?MODULE, start_link, [Ref, Config]},
       restart => permanent,
       type => worker,
       modules => [?MODULE] }.

-spec get_config(term(), override()) -> t().
%% @private
get_config(Ref, ConfigOverride) ->
    ConfigTableName = config_table_name(Ref),
    BaseConfig = maps:from_list(ets:tab2list(ConfigTableName)),
    maps:merge(BaseConfig, ConfigOverride).

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

-spec init([term() | t(), ...]) -> {ok, state()}.
%% @private
init([Ref, Config]) ->
    ConfigTableName = config_table_name(Ref),
    _ = ets:new(ConfigTableName, [named_table, protected, {read_concurrency, true}]),
    parse_and_save_config(ConfigTableName, Config),
    {ok, no_state}.

-spec handle_call(term(), {pid(), reference()}, state()) -> {noreply, state()}.
%% @private
handle_call(_Request, _From, State) ->
    {noreply, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
%% @private
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(term(), state()) -> {noreply, state()}.
%% @private
handle_info(_Info, State) ->
    {noreply, State}.

-spec terminate(term(), state()) -> ok.
%% @private
terminate(_Reason, _State) ->
    ok.

-spec code_change(term(), state(), term()) -> {ok, state()}.
%% @private
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-spec server_name(term()) -> atom().
server_name(Ref) ->
    list_to_atom("backwater_" ++ backwater_ref:to_unicode_string(Ref) ++ "_client_config").

-spec config_table_name(term()) -> atom().
config_table_name(Ref) ->
    server_name(Ref).

-spec default_connect_timeout() -> 5000.
default_connect_timeout() -> 5000.

-spec default_receive_timeout() -> 5000.
default_receive_timeout() -> 5000.

-spec default_unsafe_term_decode() -> true.
default_unsafe_term_decode() -> true.

-spec default_remote_exceptions_rethrow() -> false.
default_remote_exceptions_rethrow() -> false.

-spec parse_and_save_config(atom(), t()) -> true.
parse_and_save_config(ConfigTableName, Config) ->
    Endpoint = maps:get(endpoint, Config),
    Authentication = maps:get(authentication, Config),
    ConnectTimeout = maps:get(connect_timeout, Config, default_connect_timeout()),
    ReceiveTimeout = maps:get(receive_timeout, Config, default_receive_timeout()),
    DecodeUnsafeTerms = maps:get(decode_unsafe_terms, Config, default_unsafe_term_decode()),
    RethrowRemoteExceptions = maps:get(rethrow_remote_exceptions, Config, default_remote_exceptions_rethrow()),
    Settings =
        [{endpoint, Endpoint},
         {authentication, Authentication},
         {connect_timeout, ConnectTimeout},
         {receive_timeout, ReceiveTimeout},
         {decode_unsafe_terms, DecodeUnsafeTerms},
         {rethrow_remote_exceptions, RethrowRemoteExceptions}],
    ets:insert(ConfigTableName, Settings).
