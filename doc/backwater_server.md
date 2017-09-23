

# Module backwater_server #
* [Data Types](#types)
* [Function Index](#index)
* [Function Details](#functions)

__References__*

* [ranch:opt()](https://ninenines.eu/docs/en/ranch/1.3/manual/ranch/#_opt) documentation
* [ranch_tcp:opt()](https://ninenines.eu/docs/en/ranch/1.3/manual/ranch_tcp/#_opt) documentation
* [ranch_ssl:opt()](https://ninenines.eu/docs/en/ranch/1.3/manual/ranch_ssl/#_opt_ranch_tcp_opt_ssl_opt) documentation
* [cowboy_protocol:opts()](https://ninenines.eu/docs/en/cowboy/1.0/manual/cowboy_protocol/#opts) documentation

<a name="types"></a>

## Data Types ##




### <a name="type-clear_opt">clear_opt()</a> ###


<pre><code>
clear_opt() = <a href="ranch.md#type-opt">ranch:opt()</a> | <a href="ranch_tcp.md#type-opt">ranch_tcp:opt()</a> | {num_acceptors, non_neg_integer()}
</code></pre>




### <a name="type-clear_opts">clear_opts()</a> ###


<pre><code>
clear_opts() = [<a href="#type-clear_opt">clear_opt()</a>]
</code></pre>




### <a name="type-proto_opts">proto_opts()</a> ###


<pre><code>
proto_opts() = <a href="cowboy_protocol.md#type-opts">cowboy_protocol:opts()</a>
</code></pre>




### <a name="type-tls_opt">tls_opt()</a> ###


<pre><code>
tls_opt() = <a href="ranch.md#type-opt">ranch:opt()</a> | <a href="ranch_ssl.md#type-opt">ranch_ssl:opt()</a> | {num_acceptors, non_neg_integer()}
</code></pre>




### <a name="type-tls_opts">tls_opts()</a> ###


<pre><code>
tls_opts() = [<a href="#type-tls_opt">tls_opt()</a>]
</code></pre>

<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#start_clear-4">start_clear/4</a></td><td></td></tr><tr><td valign="top"><a href="#start_tls-4">start_tls/4</a></td><td></td></tr><tr><td valign="top"><a href="#stop_listener-1">stop_listener/1</a></td><td></td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="start_clear-4"></a>

### start_clear/4 ###

<pre><code>
start_clear(Ref, Config, TransportOpts, ProtoOpts) -&gt; {ok, pid()} | {error, term()}
</code></pre>

<ul class="definitions"><li><code>Ref = term()</code></li><li><code>Config = <a href="backwater_cowboy_handler.md#type-config">backwater_cowboy_handler:config()</a></code></li><li><code>TransportOpts = <a href="#type-clear_opts">clear_opts()</a></code></li><li><code>ProtoOpts = <a href="#type-proto_opts">proto_opts()</a></code></li></ul>

<a name="start_tls-4"></a>

### start_tls/4 ###

<pre><code>
start_tls(Ref, Config, TransportOpts, ProtoOpts) -&gt; {ok, pid()} | {error, term()}
</code></pre>

<ul class="definitions"><li><code>Ref = term()</code></li><li><code>Config = <a href="backwater_cowboy_handler.md#type-config">backwater_cowboy_handler:config()</a></code></li><li><code>TransportOpts = <a href="#type-tls_opts">tls_opts()</a></code></li><li><code>ProtoOpts = <a href="#type-proto_opts">proto_opts()</a></code></li></ul>

<a name="stop_listener-1"></a>

### stop_listener/1 ###

<pre><code>
stop_listener(Ref) -&gt; ok | {error, not_found}
</code></pre>

<ul class="definitions"><li><code>Ref = term()</code></li></ul>

