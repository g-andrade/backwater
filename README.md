

# backwater #

[![Build Status](https://travis-ci.org/g-andrade/backwater.png?branch=master)](https://travis-ci.org/g-andrade/backwater)
[![Hex pm](http://img.shields.io/hexpm/v/backwater.svg?style=flat)](https://hex.pm/packages/backwater)


### <a name="Backwater_-_Intercluster_RPC_for_Erlang_and_Elixir">Backwater - Intercluster RPC for Erlang and Elixir</a> ###

`backwater` is a library for Erlang/OTP and Elixir that allows you to
call remote modules without depending on the Erlang distribution.

Because nodes don't have to know about each other, it's ideal for situations
where machines in one datacenter need to call machines in another datacenter,
over potentially unsecure networks.


#### <a name="Usage">Usage</a> ####

Run `make console` to bring up a shell.
We're going to expose the `string` module and call it remotely.

<h5><a name="1._Generate_a_secret">1. Generate a secret</a></h5>

```erlang

Secret = crypto:strong_rand_bytes(32).

```

<h5><a name="2._Start_the_server">2. Start the server</a></h5>

```erlang


{ok, _ServerPid} =
    backwater_server:start_clear(
        #{ secret => Secret,
           exposed_modules => [{string, [{exports,all}]}]
         }).

```

<h5><a name="3._Start_the_client">3. Start the client</a></h5>

```erlang


ok = backwater_client:start(
        example,
        #{ endpoint => <<"http://127.0.0.1:8080/">>,
           secret => Secret }).

```

<h5><a name="4._Execute_a_remote_call">4. Execute a remote call</a></h5>

```erlang


{ok, "hello"} = backwater_client:call(example, string, to_lower, ["Hello"]).

```


#### <a name="Details">Details</a> ####

<h5><a name="Requirements">Requirements</a></h5>

* Erlang/OTP 19 or higher
* rebar3

For Erlang/OTP 18 support, check the 1.1.x support versions.

<h5><a name="On_serialisation">On serialisation</a></h5>


#### <a name="Alternatives_(Erlang)">Alternatives (Erlang)</a> ####


#### <a name="Alternatives_(Elixir)">Alternatives (Elixir)</a> ####


## Modules ##


<table width="100%" border="0" summary="list of modules">
<tr><td><a href="https://github.com/g-andrade/backwater/blob/master/doc/backwater_client.md" class="module">backwater_client</a></td></tr>
<tr><td><a href="https://github.com/g-andrade/backwater/blob/master/doc/backwater_cowboy_handler.md" class="module">backwater_cowboy_handler</a></td></tr>
<tr><td><a href="https://github.com/g-andrade/backwater/blob/master/doc/backwater_module_info.md" class="module">backwater_module_info</a></td></tr>
<tr><td><a href="https://github.com/g-andrade/backwater/blob/master/doc/backwater_request.md" class="module">backwater_request</a></td></tr>
<tr><td><a href="https://github.com/g-andrade/backwater/blob/master/doc/backwater_response.md" class="module">backwater_response</a></td></tr>
<tr><td><a href="https://github.com/g-andrade/backwater/blob/master/doc/backwater_server.md" class="module">backwater_server</a></td></tr>
<tr><td><a href="https://github.com/g-andrade/backwater/blob/master/doc/backwater_signatures.md" class="module">backwater_signatures</a></td></tr>
<tr><td><a href="https://github.com/g-andrade/backwater/blob/master/doc/backwater_util.md" class="module">backwater_util</a></td></tr></table>

