%%%-------------------------------------------------------------------
%% @doc exposed_ets_client public API
%% @end
%%%-------------------------------------------------------------------

-module(exposed_ets_client_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

-define(CLIENT_REF, exposed_ets_client).
-define(CLIENT_ENDPOINT, <<"http://127.0.0.1:8080/">>).

% Generate your own secret randomly e.g. using crypto:strong_rand_bytes(32).
% It must be equal to the server's.
-define(SECRET, <<"VERY_SENSITIVE_SECRET_CHANGE_THIS">>).

%%====================================================================
%% API
%%====================================================================

start(_StartType, _StartArgs) ->
    ok = backwater_client:start(
           ?CLIENT_REF,
           #{ endpoint => ?CLIENT_ENDPOINT,
              secret => ?SECRET }),
    exposed_ets_client_sup:start_link().

%%--------------------------------------------------------------------
stop(_State) ->
    ok = backwater_client:stop(?CLIENT_REF).

%%====================================================================
%% Internal functions
%%====================================================================
