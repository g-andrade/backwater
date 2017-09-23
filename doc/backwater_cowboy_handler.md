

# Module backwater_cowboy_handler #
* [Data Types](#types)

__Behaviours:__ [`cowboy_http_handler`](cowboy_http_handler.md).

<a name="types"></a>

## Data Types ##




### <a name="type-config">config()</a> ###


<pre><code>
config() = #{secret =&gt; binary(), exposed_modules =&gt; [<a href="backwater_module_info.md#type-exposed_module">backwater_module_info:exposed_module()</a>], compression_threshold =&gt; non_neg_integer(), decode_unsafe_terms =&gt; boolean(), max_encoded_args_size =&gt; non_neg_integer(), recv_timeout =&gt; timeout(), return_exception_stacktraces =&gt; boolean()}
</code></pre>




### <a name="type-state">state()</a> ###


__abstract datatype__: `state()`

