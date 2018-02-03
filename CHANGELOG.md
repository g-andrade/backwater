# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## Unreleased
### Changed
- cowboy upgraded from 2.1.0 to 2.2.2
- hackney upgraded from 1.10.1 to 1.11.0
### Removed
- rebar3 plugin (it has its own project now - rebar3_backwater)

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
