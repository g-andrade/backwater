

# Module backwater_signatures #
* [Data Types](#types)

<a name="types"></a>

## Data Types ##




### <a name="type-algorithm_failure">algorithm_failure()</a> ###


<pre><code>
algorithm_failure() = unknown_algorithm | <a href="#type-headers_failure">headers_failure()</a>
</code></pre>




### <a name="type-auth_parse_failure">auth_parse_failure()</a> ###


<pre><code>
auth_parse_failure() = invalid_auth_type | missing_authorization_header | <a href="#type-header_params_failure">header_params_failure()</a>
</code></pre>




### <a name="type-config">config()</a> ###


__abstract datatype__: `config()`




### <a name="type-header_list">header_list()</a> ###


<pre><code>
header_list() = [{binary(), binary()}]
</code></pre>




### <a name="type-header_map">header_map()</a> ###


<pre><code>
header_map() = #{binary() =&gt; binary()}
</code></pre>




### <a name="type-header_params_failure">header_params_failure()</a> ###


<pre><code>
header_params_failure() = invalid_header_params
</code></pre>




### <a name="type-headers_failure">headers_failure()</a> ###


<pre><code>
headers_failure() = missing_signed_header_list | <a href="#type-mandatory_headers_failure">mandatory_headers_failure()</a>
</code></pre>




### <a name="type-key_id_failure">key_id_failure()</a> ###


<pre><code>
key_id_failure() = unknown_key | <a href="#type-algorithm_failure">algorithm_failure()</a>
</code></pre>




### <a name="type-mandatorily_signed_headers_failure">mandatorily_signed_headers_failure()</a> ###


<pre><code>
mandatorily_signed_headers_failure() = {missing_mandatorily_signed_header, binary()} | <a href="#type-signature_failure">signature_failure()</a>
</code></pre>




### <a name="type-mandatory_headers_failure">mandatory_headers_failure()</a> ###


<pre><code>
mandatory_headers_failure() = {missing_mandatory_header, binary()} | <a href="#type-mandatorily_signed_headers_failure">mandatorily_signed_headers_failure()</a>
</code></pre>




### <a name="type-maybe_uncanonical_headers">maybe_uncanonical_headers()</a> ###


<pre><code>
maybe_uncanonical_headers() = <a href="#type-header_list">header_list()</a> | <a href="#type-header_map">header_map()</a> | {headers | ci_headers, <a href="#type-header_list">header_list()</a> | <a href="#type-header_map">header_map()</a>}
</code></pre>




### <a name="type-message">message()</a> ###


<pre><code>
message() = <a href="#type-unsigned_message">unsigned_message()</a> | <a href="#type-signed_message">signed_message()</a>
</code></pre>




### <a name="type-message_validation_success">message_validation_success()</a> ###


<pre><code>
message_validation_success() = {ok, <a href="#type-signed_message">signed_message()</a>}
</code></pre>




### <a name="type-request_id_validation_failure">request_id_validation_failure()</a> ###


<pre><code>
request_id_validation_failure() = mismatched_request_id | missing_request_id | <a href="#type-sig_parse_failure">sig_parse_failure()</a> | <a href="#type-validation_failure">validation_failure()</a>
</code></pre>




### <a name="type-request_validation_failure">request_validation_failure()</a> ###


<pre><code>
request_validation_failure() = <a href="#type-auth_parse_failure">auth_parse_failure()</a> | <a href="#type-validation_failure">validation_failure()</a>
</code></pre>




### <a name="type-response_validation_failure">response_validation_failure()</a> ###


<pre><code>
response_validation_failure() = <a href="#type-request_id_validation_failure">request_id_validation_failure()</a>
</code></pre>




### <a name="type-sig_parse_failure">sig_parse_failure()</a> ###


<pre><code>
sig_parse_failure() = missing_signature_header | <a href="#type-header_params_failure">header_params_failure()</a>
</code></pre>




### <a name="type-signature_failure">signature_failure()</a> ###


<pre><code>
signature_failure() = invalid_signature | <a href="#type-signature_string_failure">signature_string_failure()</a>
</code></pre>




### <a name="type-signature_string_failure">signature_string_failure()</a> ###


<pre><code>
signature_string_failure() = {missing_header, binary()}
</code></pre>




### <a name="type-signed_message">signed_message()</a> ###


__abstract datatype__: `signed_message()`




### <a name="type-unsigned_message">unsigned_message()</a> ###


__abstract datatype__: `unsigned_message()`




### <a name="type-validation_failure">validation_failure()</a> ###


<pre><code>
validation_failure() = <a href="#type-key_id_failure">key_id_failure()</a>
</code></pre>

