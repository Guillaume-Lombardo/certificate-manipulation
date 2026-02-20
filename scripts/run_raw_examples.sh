#!/bin/zsh
set -euo pipefail

help_output="$(uv run certificate-manipulation --help)"
echo "$help_output"

if print -r -- "$help_output" | grep -Eq '\bcombine\b|\bsplit\b|\bfilter\b'; then
  : "${bundle_in:=data/raw/bundle.pem}"
  : "${combined_out:=data/out/combined.pem}"
  : "${split_outdir:=data/out/split}"
  : "${filtered_out:=data/out/filtered.pem}"

  uv run certificate-manipulation combine --input "$bundle_in" --output "$combined_out"
  uv run certificate-manipulation split --input "$combined_out" --output-dir "$split_outdir"
  uv run certificate-manipulation filter --input "$combined_out" --output "$filtered_out"
else
  echo "No combine/split/filter subcommands detected yet; running smoke checks only."
  uv run certificate-manipulation --version
fi
