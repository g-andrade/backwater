# backwater

Erlang/OTP library for intercluster RPC **without** the Erlang distribution
protocol. It exposes selected modules over HTTP(S) (built on `cowboy` on the
server side and `hackney` on the client side) so nodes in one datacenter can
call nodes in another over unsecure or unstable networks. Works from Elixir too.
All requests and responses are authenticated and signed (a modified HTTP
Signatures scheme); payloads use the Erlang external term format with optional
gzip compression and configurable size/safety limits.

## Build, test, check

```bash
make compile         # compile
make test            # eunit + CT (+ coverage)
make check           # check-fast + check-slow
make check-fast      # format check (erlfmt) + xref + dead-code (hank) + lint (elvis)
make check-slow      # dialyzer (run under the ranch2 profile; see below)
make format          # auto-format source with erlfmt
make eunit           # unit tests only
make ct              # common test suites + coverage
make dialyzer        # type analysis (ranch2 profile)
make doc             # EEP-48 chunks via `rebar3 edoc`, rendered by the ex_doc escript
make shell           # interactive REPL with the app started
```

All checks run sequentially (`.NOTPARALLEL`). CI runs `make check-fast`,
`make test`, an extra `rebar3 as ranch2 do ct, eunit`, then `make check-slow`,
over OTP 24–29 on Linux.

## Compiler flags

Always on: `warn_export_vars`, `warn_missing_spec`, `warn_unused_import`,
`warnings_as_errors`. Every exported function must have a `-spec`. The `shell`
and `test` profiles relax `warn_missing_spec` and `warnings_as_errors`.

## Architecture

```
backwater_app
└── backwater_sup            (top supervisor)
    └── backwater_cache      (gen_server; ETS-backed cache of exposed-module
                              function properties, with periodic expiry)
```

The **server side** is started on demand by `backwater:start_clear_server/2,4`
and `backwater:start_tls_server/3,4`, which stand up a `cowboy` listener (under
ranch's own supervision, not `backwater_sup`) routed to `backwater_cowboy_handler`.
The handler runs a fixed request pipeline (authenticate → authorize → resolve
target → negotiate content type/encoding → decode args → execute → respond).

The **client side** is `backwater:call/4,5`: `backwater_request:encode` builds a
signed HTTP request, `hackney` sends it, and `backwater_response:decode`
verifies and decodes the reply. `backwater_request`/`backwater_response` are also
the public seam for plugging in an alternative HTTP client.

### Key modules

| Module | Role |
|---|---|
| `backwater` | Public API: `call/4,5`, `start_clear_server/2,4`, `start_tls_server/3,4`, `stop_server/0,1` |
| `backwater_app` / `backwater_sup` | OTP application and top supervisor |
| `backwater_cache` | `gen_server` over ETS; caches exposed-module function properties |
| `backwater_cowboy_handler` | Server-side cowboy handler; the request pipeline |
| `backwater_module_exposure` | Interprets the exposed-module specs; introspects exported functions |
| `backwater_request` / `backwater_response` | Client-side request encoding / response decoding |
| `backwater_signatures` | HTTP-signatures-based authentication and integrity |
| `backwater_media_etf` | External term format codec, refusing unsafe/compressed-bomb payloads |
| `backwater_encoding_gzip` | gzip (de)compression |
| `backwater_header_params` | HTTP header parameter parsing |
| `backwater_util` / `backwater_sup_util` | Small helpers |

## Code conventions

- `backwater` is the only public, documented module; everything else is internal.
- **Documentation is EEP-48 native**, guarded by `-ifdef(E48)` (OTP 27+):
  `-moduledoc`/`-doc` on the public `backwater` module, and **`-moduledoc false`
  / `-doc false` to hide internals — NOT `%% @private`, which ex_doc ignores.
  Do not reintroduce `@private`/`@doc`/`@spec` tags.
- Docs are built by `make doc` = `rebar3 edoc` (driven by the top-level
  `edoc_opts` with `{preprocess, true}` + the chunk doclet/layout, emitting into
  `_build/docs/lib/backwater/ebin`) followed by the ex_doc escript over those
  chunks using `ex_doc.config`. There is **no** `docs` rebar3 profile.
  `ex_doc.config` silences undefined/hidden reference warnings on the whole
  `backwater` module (its public specs reference external ranch/cowboy types and
  a few intentionally hidden internal types; the escript can't resolve either,
  and only supports per-referencing-module suppression).
- Code is formatted with `erlfmt`; run `make format` before committing. The
  reformat commit is recorded in `.git-blame-ignore-revs`.
- Elvis/hank exceptions are documented inline in `elvis.config` / `rebar.config`:
  dynamic dispatch (`no_invalid_dynamic_calls`) is intrinsic to an RPC library;
  `export_used_types` is off (internal types used by cowboy callbacks);
  `function_naming_convention` is relaxed for the `decode_`-style workers and the
  `'_call'` common-test back door; `dont_repeat_yourself` is off because eunit
  suites are embedded in the modules under `-ifdef(TEST)`; hank ignores
  `single_use_hrl_attrs` on the two headers that centralize defaults/macros.

## Tests

- `test/backwater_SUITE.erl` — the Common Test suite (client↔server round trips
  over HTTP and HTTPS, content negotiation, signatures, error paths). TLS test
  material is in `test/data/ssl/`.
- Several modules also carry eunit tests inline under `-ifdef(TEST)`.
- `backwater:'_call'/6` is an underscore-prefixed test-only back door (exported
  under `-ifdef(TEST)`) that lets suites override request fields.

## OTP versions / dependencies

- Supported OTP range is **24–29**. `minimum_otp_vsn` is declared as `"22"` with
  a `% but only 24+ is supported` comment.
- `rebar.config.script` drops dev plugins per OTP version: erlfmt + hank + elvis
  on OTP ≤ 25; erlfmt alone on OTP ≤ 26 (its `-doc` triple-quoted strings break
  katana_code there); hank on OTP 29 (katana_code/hank bug).
- Runtime deps: `cowboy ~> 2.9` (server) and `hackney ~> 1.17` (client). cowboy
  spans ranch 1.8–3.0; the default build resolves the floor (ranch 1.8) and the
  `ranch2` profile resolves ranch 2.x. CI tests **both** lines, and dialyzer runs
  under `ranch2` because ranch 1.8 references `ssl_cipher:erl_cipher_suite/0`, a
  type removed from modern OTP.

## Releasing

`make publish` builds the docs and runs `rebar3 hex publish --doc-dir=doc`.
Versioning follows SemVer; history is in `CHANGELOG.md` (Keep a Changelog format).
