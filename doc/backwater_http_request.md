

# Module backwater_http_request #
* [Data Types](#types)
* [Function Index](#index)
* [Function Details](#functions)

<a name="types"></a>

## Data Types ##




### <a name="type-nonempty_headers">nonempty_headers()</a> ###


<pre><code>
nonempty_headers() = [{<a href="#type-nonempty_binary">nonempty_binary()</a>, binary()}, ...]
</code></pre>




### <a name="type-state">state()</a> ###


<pre><code>
state() = #{signed_request_msg =&gt; <a href="backwater_http_signatures.md#type-signed_message">backwater_http_signatures:signed_message()</a>}
</code></pre>




### <a name="type-t">t()</a> ###


<pre><code>
t() = {Method::<a href="#type-nonempty_binary">nonempty_binary()</a>, Url::<a href="#type-nonempty_binary">nonempty_binary()</a>, Headers::<a href="#type-nonempty_headers">nonempty_headers()</a>, Body::binary()}
</code></pre>

<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#encode-5">encode/5</a></td><td></td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="encode-5"></a>

### encode/5 ###

<pre><code>
encode(Endpoint, Module, Function, Args, Secret) -&gt; {Request, RequestState}
</code></pre>

<ul class="definitions"><li><code>Endpoint = <a href="#type-nonempty_binary">nonempty_binary()</a></code></li><li><code>Module = module()</code></li><li><code>Function = atom()</code></li><li><code>Args = [term()]</code></li><li><code>Secret = binary()</code></li><li><code>Request = <a href="#type-t">t()</a></code></li><li><code>RequestState = <a href="#type-state">state()</a></code></li></ul>

