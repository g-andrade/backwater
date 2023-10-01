# backwater

**This library is not under continuous maintenance; if you'd like to perform
maintenance yourself, feel free to open an issue requesting access.**

[![](https://img.shields.io/hexpm/v/backwater.svg?style=flat)](https://hex.pm/packages/backwater)
[![](https://github.com/g-andrade/backwater/actions/workflows/ci.yml/badge.svg)](https://github.com/g-andrade/backwater/actions/workflows/ci.yml)
[![Erlang Versions](https://img.shields.io/badge/Supported%20Erlang%2FOTP-22%20to%2026-blue)](https://www.erlang.org)

### Backwater - Intercluster RPC for Erlang and Elixir

`backwater` allows you to call remote modules without depending on the
Erlang distribution protocol.

It's targeted at scenarios where nodes in one datacenter need to call
nodes in another datacenter, over unsecure or unstable networks.

#### Usage

Run `make shell` to bring up a shell. We're going to expose the
`string` module and call it remotely.

##### 1. Generate a secret

``` erlang
Secret = crypto:strong_rand_bytes(32).
```

##### 2. Start the server

``` erlang
backwater:start_clear_server(Secret, [string]).
% {ok, _ServerPid}
```

##### 3. Execute a remote call

``` erlang
backwater:call({"127.0.0.1", Secret}, string, to_upper, ["hello"]).
% {ok, "HELLO"}
```

#### Details

`backwater` is built on top of
[cowboy](https://github.com/ninenines/cowboy) and
[hackney](https://github.com/benoitc/hackney).

##### Requirements

  - Erlang/OTP 22 or higher
  - rebar3

##### Documentation

Documentation is hosted on [HexDocs](https://hexdocs.pm/backwater/).

##### Authentication and integrity

All requests and responses are authenticated and signed using a modified
version of [HTTP
signatures](https://tools.ietf.org/id/draft-cavage-http-signatures-07.txt);
nevertheless, it's **strongly** recommended to use HTTPS, as HTTP
signatures offer no protection against replay attacks - besides risking
exposure of sensitive data.

##### Exceptions

By default, remote exceptions are returned as errors on the caller's
side. This behaviour can be tweaked using the
`rethrow_remote_exceptions` flag in `:call/5` options.

Remote stack traces are returned by default. Because they are
computationally expensive to generate, this behaviour can be can be
changed using the `return_exception_stacktraces` flag in
`:start_clear_server` / `:start_tls_server` backwater options.

##### Serialisation

The [external term format](http://erlang.org/doc/apps/erts/erl_ext_dist)
is used for all function arguments and return values.

Because trust is assumed unless declared otherwise (like in regular
Erlang clusters), unsafe terms are decoded by default.

For function arguments, this behaviour can be tweaked through the
`decode_unsafe_terms` setting in backwater options when running
`:start_clear_server` or `:start_tls_server`.

For return values, this behaviour can be tweaked through the
`decode_unsafe_terms` setting in `:call/5` options.

##### Compression

By default, both serialised function arguments and serialised return
values larger than 300 bytes are subject to attempted compression using
gzip. The actual compression result is only used if it is indeed smaller
than the original payload.

For function arguments, this threshold can be tweaked through the
`compression_threshold` setting in `:call/5` options.

For return values, this threshold can be tweaked through the
`compression_threshold` setting in backwater options when running
`:start_clear_server` or `:start_tls_server`.

##### Payload limits

By default, both serialised function arguments and serialised return
values larger than 8 MiB are rejected (independently of whether they're
transmitted in compressed form or not.)

For function arguments, this limit (in bytes) can be adjusted using the
`max_encoded_args_size` setting in backwater options when running
`:start_clear_server` or `:start_tls_server`.

For return values, this limit (in bytes) can be adjusted using the
`max_encoded_result_size` setting in `:call/5` options.

##### Timeouts and ports

The default listen port for HTTP is 8080; for HTTPS, it's 8443. This can
be adjusted on server using the `http` options, and on clients by
specifying it in `Endpoint`.

The client enforces a default connection timeout of 8s, and a receive
timeout of 5s. Either can be adjusted using either `connect_timeout` or
`recv_timeout`, respectively, in `:call/5` options.

The server enforces a default receive timeout of 5s. This can be
adjusted using the `recv_timeout` setting in backwater options, when
running `:start_clear_server` or `:start_tls_server`.

##### On using alternative HTTP clients

For now, the best way to achieve this is to build requests using the
`backwater_request` module and interpret responses using the
`backwater_response` module.

#### License

MIT License

Copyright (c) 2017-2022 Guilherme Andrade

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
