#!/bin/bash

PROJ_DIR="$(dirname $0)/.."
BENCH_DIR="$PROJ_DIR/benchmark"

# Does not handle white chars in path i.e. space, tab etc.
to_native=$(find $BENCH_DIR -name \*.dart)

rm -rf bin && mkdir "$PROJ_DIR/bin"

# Build
echo "Building benchmark files"
for source in $to_native
do
    file=$(basename $source .dart)
    echo "- $file"
    dart2native "$source" --output "$PROJ_DIR/bin/$file"
done

# Run
echo "Running built benchmark files"
for bin_file in $to_native
do
    file=$(basename $bin_file .dart)
    echo "Running $file"
    "$PROJ_DIR/bin/$file"
done

echo "Deleting files..."

[ -n "$PROJ_DIR"] && rm -f "$PROJ_DIR/bin"
