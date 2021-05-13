# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Removed
- support for OTP 20
- support for OTP 21

## [3.4.0] - 2020-05-26
### Fixed
- compilation errors on OTP 23

## [3.3.0] - 2019-11-11
### Changed
- imported `cowboy` version from 2.6.3 to 2.7.0
### Removed
- OTP 19 support

## [3.2.1] - 2019-09-25
### Fixed
- broken HTTPS-transported calls on OTP 22.1

## [3.2.0] - 2019-07-10
### Changed
- cowboy was upgraded from 2.6.1 to 2.6.3
- hackney was upgraded from 1.11.0 to 1.15.0
### Fixed
- failure to decompress data on OTP 22 (as reported by AlexKovalevych on GitHub)

## [3.1.0] - 2019-01-19
### Changed
- cowboy was upgraded from 2.2.2 to 2.6.1
- hackney was upgraded from 1.11.0 to 1.15.0

## [3.0.3] - 2019-01-19
### Removed
- outdated mention of boilerplate generator plugin which was never finished
### Fixed
- unwarranted import of `rebar3_hex` plugin in library consumers

## [3.0.2] - 2018-06-20
### Fixed
- OTP 21 compatibility

## [3.0.1] - 2018-03-29
### Changed
- documentation is now published to HexDocs

## [3.0.0] - 2018-02-04
### Changed
- unsafe arguments and return values are now decoded by default (trust is assumed)
- the default exposure policy, per module, from `use_backwater_attributes` to `all` (see migration guide)
- the `backwater_http_request` module was renamed to `backwater_request`
- the `backwater_http_response` module was renamed to `backwater_response`
- the `backwater_http_signatures` module was renamed to `backwater_signatures`
- `backwater_client:call/4` is now `backwater:call/5` (see migration guide)
- `backwater_server:start_clear/4` is now `backwater:start_clear_server/4` (see migration guide)
- `backwater_server:start_tls/4` is now `backwater:start_tls_server/4` (see migration guide)
- `backwater_server:stop_listener/1` is now `backwater:stop_server/1` (see migration guide)
- cowboy was upgraded from 2.1.0 to 2.2.2
- hackney was upgraded from 1.10.1 to 1.11.0
### Removed
- rebar3 plugin (it has its own project now - `rebar3_backwater`; see migration guide)
- support for defining module exposure through custom `backwater_export` attributes and functions (see migration guide)
- support for defining proto / HTTP options as a proplist

## [2.0.2] - 2018-02-03
### Fixed
- Occasional crash of rebar3 plugin on macOS

## [1.1.1] - 2018-02-03
### Fixed
- Occasional crash of rebar3 plugin on macOS

## [2.0.1] - 2018-01-27
### Added
- Enforcement of minimum OTP version on rebar.config

## [1.1.0] - 2018-01-27
### Added
- OTP 18 support

## [2.0.0] - 2017-11-18
### Added
- Support for specifying cowboy start-up options as a map (see info on upgrade below)
### Changed
- Request type was transformed from a tuple into a more detailed map (breaking change)
- cowboy upgraded from 1.1.2 to 2.1.0 (breaking change)
- hackney upgraded from 1.9.0 to 1.10.1
### Removed
- Hackish request retry mechanism that tried to work around rare premature connection closures in hackney

## [1.0.0] - 2017-09-23
### Added
- Exposure of arbitrary modules
- Exposure of arbitrary functions within said modules using custom attributes (Erlang)
- Exposure of arbitrary functions within said modules using custom export function (Elixir)
- Support for multiple, independent instances of both client and server
- Sign all requests and responses using a modified version of HTTP signatures
- rebar3 plugin for client code boilerplate generation
