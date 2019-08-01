#!/bin/bash

#rm -rdf cxx
cp -r ../cxx/grpc grpc
cp -r ../cxx/util util

make check
make all
#rm -rdf cxx
