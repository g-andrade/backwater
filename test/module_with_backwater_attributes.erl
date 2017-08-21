%% Copyright (c) 2017 Guilherme Andrade <backwater@gandrade.net>
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

-module(module_with_backwater_attributes).

-export([exported_functionA/0]).
-export([exported_functionB/1]).
-export([exported_functionC/0]).
-export([exported_functionD/1]).

% single export
-backwater_export({exported_functionA,0}).

% export list
-backwater_export([{exported_functionC,0},
                   {exported_functionD,1},
                   {exported_functionE,0}]).

exported_functionA() ->
    internal_function({foobar}).

exported_functionB(V) ->
    internal_function({V}).

exported_functionC() ->
    internal_function({barfoo}).

exported_functionD(V) ->
    internal_function({V}).

internal_function(V) ->
    V.
