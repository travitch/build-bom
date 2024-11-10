#!/usr/bin/env bash

for X in build_bom_seq ; do
    nix run nixpkgs#d2 -- -t 104 -l elk $X.d2
    nix shell nixpkgs#imagemagick -c convert -size 2048x2048 $X.svg $X.png
done
