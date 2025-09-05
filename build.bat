@echo off

mkdir thirdparty\capstone\.build 2> NUL
pushd thirdparty\capstone\.build
cmake .. -DCMAKE_INSTALL_PREFIX=..\.install
cmake --build . --config Debug
cmake --install . --config Debug
popd

mkdir .build 2> NUL
pushd .build
cmake ..
popd
