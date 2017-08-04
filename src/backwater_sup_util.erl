%% @private
-module(backwater_sup_util).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type start_link_ret() ::
        {ok, pid()} | {error, {already_started, pid()} | {shutdown, term()} | term()}.
-export_type([start_link_ret/0]).

-type start_child_ret() ::
        {ok, Child :: undefined | pid()} |
        {ok, Child :: undefined | pid() | term()} |
        {error, already_present | {already_started, Child :: undefined | pid()} | term()}.
-export_type([start_child_ret/0]).

-type stop_child_ret() :: ok | {error, terminate_child_error() | delete_child_error()}.
-export_type([stop_child_ret/0]).

-type terminate_child_error() :: not_found | simple_one_for_one.
-export_type([terminate_child_error/0]).

-type delete_child_error() :: running | restarting | not_found | simple_one_for_one.
-export_type([delete_child_error/0]).
