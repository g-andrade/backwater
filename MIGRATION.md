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

## From [1.x] to [2.x]
### Update
- any uses or assumptions of the request returned by backwater_http_request:encode/{5,6}, which was a 4-tuple, to deal with a map instead (see structure in docs.)
- any dependencies on cowboy 1.x to cowboy 2.x
