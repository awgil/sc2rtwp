@echo off

mkdir .build 2> NUL
pushd .build
cmake ..
popd
