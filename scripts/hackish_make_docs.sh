#!/usr/bin/env bash
set -ex

# sigh.....
rebar3 as generate_documentation compile
mkdir -p _build/generate_documentation/lib/backwater/doc/
cp -p overview.edoc _build/generate_documentation/lib/backwater/doc/
erl -pa _build/generate_documentation/lib/*/ebin -noshell -run edoc_run application "backwater"
erl -pa _build/generate_documentation/lib/*/ebin -noshell -run edoc_run application "backwater" '[{doclet, edown_doclet}, {top_level_readme, {"README.md", "https://github.com/g-andrade/backwater", "master"}}]'
rm -rf doc
mv _build/generate_documentation/lib/backwater/doc ./
sed -i -e 's/^\(---------\)$/\n\1/g' README.md
