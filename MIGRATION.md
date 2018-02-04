# Migration Plan

## From [2.x] to [3.x]
### Update
- your declaration of the rebar3 plugin import (if using), like this:
```
    % change this
    {plugins, [{backwater, "2.0.2"}]}.

    % into this
    {plugins, [{rebar3_backwater, "1.0.0"}]}.
```
- calls to `backwater_server:start_clear/4` to `backwater:start_clear_server/4`, like this:
```
    % change this
    backwater_server:start(Ref,
                           #{ secret => Secret, exposed_modules => ExposedModules, ...BackwaterOpts... },
                           TransportOpts, HttpOpts).

    % into this
    Opts = #{ transport => TransportOpts, http => HttpOpts, backwater => BackwaterOpts },
    backwater:start_clear_server(Ref, Secret, ExposedModules, Opts).
```
- calls to `backwater_server:start_tls/4` to `backwater:start_tls_server/4`, like this:
```
    % change this
    backwater_server:start(Ref,
                           #{ secret => Secret, exposed_modules => ExposedModules, ...BackwaterOpts... },
                           TransportOpts, HttpOpts).

    % into this
    Opts = #{ transport => TransportOpts, http => HttpOpts, backwater => BackwaterOpts },
    backwater:start_tls_server(Ref, Secret, ExposedModules, Opts).
```
- calls to `backwater_server:stop_listener/1` to `backwater:stop_server/1`
- calls to `backwater_client:call/4`, like this:
```
    % change these
    backwater_client:start(Ref, #{ endpoint => Location, secret => Secret }),
    backwater_client:call(Ref, Module, Function, Args).

    % into either of these (depending on whether you.re overriding default options)
    backwater:call({Location, Secret}, Module, Function, Args).
    backwater:call({Location, Secret}, Module, Function, Args, Options).
```
- calls to `backwater_http_response` module (rename to `backwater_response`)
- calls to `backwater_http_signatures` module (rename to `backwater_signatures`)
- calls to `backwater_http_request:encode/4`, like this:
```
    % change this
    backwater_http_request:encode(Location, Module, Function, Args, Secret)

    % into this
    backwater_request:encode({Location, Secret}, Module, Function, Args)
```
- any use of the `backwater_http_request:encode/5`, like this:
```
    % change this
    backwater_http_request:encode(Location, Module, Function, Args, Secret, Options)

    % into this
    backwater_request:encode({Location, Secret}, Module, Function, Args, Options)
```
- use of custom `backwater_export` attributes (Erlang), like this:
```
    % remove this from your Erlang module
    -module(foo)
    -backwater_export({bar,3}).

    % and declare it upon server start instead
    backwater:start_clear_server(Secret, [{foo, [{exports,[{bar,3}]}]}]).
```
- use of custom `backwater_export` functions (Elixir), like this:
```
    % remove this from your Elixir module
    defmodule Foo do
        def backwater_export do
            [{:bar,3}]
        end

    % and declare it upon server start instead
    :backwater.start_clear_server(secret, [{Foo, [{:exports,[{:bar,3}]}]}])
```
### Delete
- Calls to `backwater_client:start/2`
- Calls to `backwater_client:stop/1`
- Custom `backwater_export` module attributes

## From [1.x] to [2.x]
### Update
- any uses or assumptions of the request returned by backwater_http_request:encode/{5,6}, which was a 4-tuple, to deal with a map instead (see structure in docs.)
- any dependencies on cowboy 1.x to cowboy 2.x
