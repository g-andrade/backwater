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

%% @private
-module(backwater_cowboy2_req).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([header/2]).
-export([headers/1]).
-export([method/1]).
-export([parse_header/2]).
-export([path/1]).
-export([path_info/1]).
-export([qs/1]).
-export([read_body/2]).
-export([reply/4]).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type t() :: cowboy_req:req().
-export_type([t/0]).

-type http_headers() :: cowboy:http_headers().
-export_type([http_headers/0]).

-type path_info() :: cowboy_router:tokens().
-export_type([path_info/0]).

-type read_body_opts() :: cowboy_req:read_body_opts().
-export_type([read_body_opts/0]).

-type status() :: cowboy:http_status().
-export_type([status/0]).

-type resp_body() :: cowboy_req:resp_body().
-export_type([resp_body/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec header(binary(), t()) -> binary() | undefined.
header(Name, Req) ->
    cowboy_req:header(Name, Req).

-spec headers(t()) -> http_headers().
headers(Req) ->
    cowboy_req:headers(Req).

-spec method(t()) -> binary().
method(Req) ->
    cowboy_req:method(Req).

-spec parse_header(binary(), t()) -> any().
parse_header(Name, Req) ->
    cowboy_req:parse_header(Name, Req).

-spec path(t()) -> binary().
path(Req) ->
    cowboy_req:path(Req).

-spec path_info(t()) -> cowboy_router:tokens() | undefined.
path_info(Req) ->
    cowboy_req:path_info(Req).

-spec qs(t()) -> binary().
qs(Req) ->
    cowboy_req:qs(Req).

-spec read_body(t(), read_body_opts()) -> {ok, binary(), t()} | {more, binary(), t()}.
read_body(Req, Opts) ->
    cowboy_req:read_body(Req, Opts).

-spec reply(status(), http_headers(), resp_body(), t()) -> t().
reply(Status, Headers, RespBody, Req) ->
    cowboy_req:reply(Status, Headers, RespBody, Req).
