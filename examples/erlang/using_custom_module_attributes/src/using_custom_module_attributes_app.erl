%%%-------------------------------------------------------------------
%% @doc using_custom_module_attributes public API
%% @end
%%%-------------------------------------------------------------------

-module(using_custom_module_attributes_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

-define(SERVER_REF, using_custom_module_attributes).
-define(SERVER_PORT, 8080).

% Generate your own secret randomly e.g. using crypto:strong_rand_bytes(32).
% It must be equal to the client's.
-define(SECRET, <<"VERY_SENSITIVE_SECRET_CHANGE_THIS">>).

%%====================================================================
%% API
%%====================================================================

start(_StartType, _StartArgs) ->
    {ok, _Pid} =
        backwater_server:start_clear(
          ?SERVER_REF,
          #{ secret => ?SECRET,
             exposed_modules => [module_with_custom_attributes] },
          [{port, ?SERVER_PORT}],
          []),
    using_custom_module_attributes_sup:start_link().

%%--------------------------------------------------------------------
stop(_State) ->
    ok = backwater_server:stop_listener(?SERVER_REF).

%%====================================================================
%% Internal functions
%%====================================================================
