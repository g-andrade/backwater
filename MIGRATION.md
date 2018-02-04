# Migration Plan

## From [2.x] to UNRELEASED
### Update
- your declaration of the rebar3 plugin import (if using), like this:
```
    % change this
    {plugins, [{backwater, "2.0.2"}]}.

    % into this
    {plugins, [{rebar3_backwater, "1.0.0"}]}.
```
- calls to `backwater_client:call/4`, like this:
```
    % change this
    backwater_client:start(Ref, #{ endpoint => Location, secret => Secret }),
    backwater_client:call(Ref, Module, Function, Args).

    % into either of these (depending on whether you.re overriding default options)
    backwater_client:call({Location, Secret}, Module, Function, Args).
    backwater_client:call({Location, Secret}, Module, Function, Args, Options).
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
### Delete
- Calls to `backwater_http_client:start/2`
- Calls to `backwater_http_client:stop/1`

## From [1.x] to [2.x]
### Update
- any uses or assumptions of the request returned by backwater_http_request:encode/{5,6}, which was a 4-tuple, to deal with a map instead (see structure in docs.)
- any dependencies on cowboy 1.x to cowboy 2.x
