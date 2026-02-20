#!/bin/zsh
set -euo pipefail

help_output="$(uv run certificate-manipulation --help)"
echo "$help_output"

if print -r -- "$help_output" | grep -Eq '\bcombine\b|\bsplit\b|\bconvert\b|\bfilter\b'; then
  : "${cert1:=data/raw/cert-1.crt}"
  : "${cert2:=data/raw/cert-2.crt}"
  : "${combined_out:=data/out/combined.pem}"
  : "${split_outdir:=data/out/split}"
  : "${converted_out:=data/out/cert-1.pem}"
  : "${filtered_out:=data/out/filtered.pem}"

  uv run certificate-manipulation combine --inputs "$cert1" "$cert2" --output "$combined_out"
  uv run certificate-manipulation split --input "$combined_out" --output-dir "$split_outdir"
  uv run certificate-manipulation convert --input "$cert1" --output "$converted_out" --to pem
  uv run certificate-manipulation filter --input "$combined_out" --output "$filtered_out" --subject-cn cert-1
else
  echo "No combine/split/convert/filter subcommands detected yet; running smoke checks only."
  uv run certificate-manipulation --version
fi
