#!/bin/bash

rm -rdf grpc util 
cp -r ../cxx/grpc grpc
cp -r ../cxx/util util

make all
rm -rdf grpc util
