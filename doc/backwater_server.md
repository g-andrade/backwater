

# Module backwater_server #
* [Function Index](#index)
* [Function Details](#functions)

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

<ul class="definitions"><li><code>Ref = term()</code></li><li><code>Config = <a href="backwater_cowboy_handler.md#type-config">backwater_cowboy_handler:config()</a></code></li><li><code>TransportOpts = <a href="ranch_tcp.md#type-opts">ranch_tcp:opts()</a></code></li><li><code>ProtoOpts = <a href="cowboy.md#type-opts">cowboy:opts()</a></code></li></ul>

<a name="start_tls-4"></a>

### start_tls/4 ###

<pre><code>
start_tls(Ref, Config, TransportOpts, ProtoOpts) -&gt; {ok, pid()} | {error, term()}
</code></pre>

<ul class="definitions"><li><code>Ref = term()</code></li><li><code>Config = <a href="backwater_cowboy_handler.md#type-config">backwater_cowboy_handler:config()</a></code></li><li><code>TransportOpts = <a href="ranch_ssl.md#type-opts">ranch_ssl:opts()</a></code></li><li><code>ProtoOpts = <a href="cowboy.md#type-opts">cowboy:opts()</a></code></li></ul>

<a name="stop_listener-1"></a>

### stop_listener/1 ###

<pre><code>
stop_listener(Ref) -&gt; ok | {error, not_found}
</code></pre>

<ul class="definitions"><li><code>Ref = term()</code></li></ul>

