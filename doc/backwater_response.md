

# Module backwater_response #
* [Data Types](#types)
* [Function Index](#index)
* [Function Details](#functions)

<a name="types"></a>

## Data Types ##




### <a name="type-error">error()</a> ###


<pre><code>
error() = {exception, {Class::error | exit | throw, Reason::term(), <a href="erlang.md#type-raise_stacktrace">erlang:raise_stacktrace()</a>}} | {<a href="#type-failure">failure()</a>, <a href="#type-raw_response">raw_response()</a>}
</code></pre>




### <a name="type-failure">failure()</a> ###


<pre><code>
failure() = {response_authentication, <a href="#type-response_authentication_failure">response_authentication_failure()</a>} | <a href="#type-response_decode_failure">response_decode_failure()</a> | remote
</code></pre>




### <a name="type-headers">headers()</a> ###


<pre><code>
headers() = [{<a href="#type-nonempty_binary">nonempty_binary()</a>, binary()}]
</code></pre>




### <a name="type-options">options()</a> ###


<pre><code>
options() = #{decode_unsafe_terms =&gt; boolean(), max_encoded_result_size =&gt; non_neg_integer(), rethrow_remote_exceptions =&gt; boolean()}
</code></pre>




### <a name="type-raw_response">raw_response()</a> ###


<pre><code>
raw_response() = {<a href="#type-status_code_name">status_code_name()</a>, CiHeaders::<a href="#type-headers">headers()</a>, RawBody::binary()}
</code></pre>




### <a name="type-response_authentication_failure">response_authentication_failure()</a> ###


<pre><code>
response_authentication_failure() = <a href="backwater_signatures.md#type-response_validation_failure">backwater_signatures:response_validation_failure()</a> | wrong_body_digest
</code></pre>




### <a name="type-response_decode_failure">response_decode_failure()</a> ###


<pre><code>
response_decode_failure() = invalid_content_encoding | invalid_content_type | invalid_body
</code></pre>




### <a name="type-status_code">status_code()</a> ###


<pre><code>
status_code() = pos_integer()
</code></pre>




### <a name="type-status_code_name">status_code_name()</a> ###


<pre><code>
status_code_name() = ok | bad_request | unauthorized | forbidden | not_found | not_acceptable | payload_too_large | unsupported_media_type | internal_error | {http, <a href="#type-status_code">status_code()</a>}
</code></pre>




### <a name="type-t">t()</a> ###


<pre><code>
t(OtherError) = {ok, Value::term()} | {error, <a href="#type-error">error()</a> | OtherError} | no_return()
</code></pre>




### <a name="type-t">t()</a> ###


<pre><code>
t() = {ok, Value::term()} | {error, <a href="#type-error">error()</a>} | no_return()
</code></pre>

<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#decode-4">decode/4</a></td><td></td></tr><tr><td valign="top"><a href="#decode-5">decode/5</a></td><td></td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="decode-4"></a>

### decode/4 ###

<pre><code>
decode(StatusCode, Headers, Body, RequestState) -&gt; Response | no_return()
</code></pre>

<ul class="definitions"><li><code>StatusCode = <a href="#type-status_code">status_code()</a></code></li><li><code>Headers = <a href="#type-headers">headers()</a></code></li><li><code>Body = binary()</code></li><li><code>RequestState = <a href="backwater_request.md#type-state">backwater_request:state()</a></code></li><li><code>Response = <a href="#type-t">t()</a></code></li></ul>

<a name="decode-5"></a>

### decode/5 ###

<pre><code>
decode(StatusCode, Headers, Body, RequestState, Options) -&gt; Response | no_return()
</code></pre>

<ul class="definitions"><li><code>StatusCode = <a href="#type-status_code">status_code()</a></code></li><li><code>Headers = <a href="#type-headers">headers()</a></code></li><li><code>Body = binary()</code></li><li><code>RequestState = <a href="backwater_request.md#type-state">backwater_request:state()</a></code></li><li><code>Options = <a href="#type-options">options()</a></code></li><li><code>Response = <a href="#type-t">t()</a></code></li></ul>

