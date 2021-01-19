#!/bin/bash

for i in $(ls -1 ../example/);
do
  B=$(basename $i .dart)
  O="$B.js"
  dart2js ../example/$i -o "$B.js"
  sed -i '/^(function dartProgram() {/r ../tool/dart_crypto.js' "$B.js"
done
for i in $(ls -1 ../benchmark/);
do
  B=$(basename $i .dart)
  O="$B.js"
  dart2js ../benchmark/$i -o "$B.js"
  sed -i '/^(function dartProgram() {/r ../tool/dart_crypto.js' "$B.js"
done

