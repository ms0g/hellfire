#!/bin/bash
mkdir -p build_temp && cd build_temp || exit
cmake -DCMAKE_BUILD_TYPE=Release ../.. && cmake --build .