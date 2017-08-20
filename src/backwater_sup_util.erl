%% @copyright 2017 Guilherme Andrade <backwater@gandrade.net>
%%
%% Permission is hereby granted, free of charge, to any person obtaining a
%% copy  of this software and associated documentation files (the "Software"),
%% to deal in the Software without restriction, including without limitation
%% the rights to use, copy, modify, merge, publish, distribute, sublicense,
%% and/or sell copies of the Software, and to permit persons to whom the
%% Software is furnished to do so, subject to the following conditions:
%%
%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.
%%
%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
%% DEALINGS IN THE SOFTWARE.

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
