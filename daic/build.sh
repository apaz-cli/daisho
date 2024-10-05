#!/bin/sh

pgen -p daisho_parser daisho.peg

cd daisho_parser/
python setup.py build_ext --inplace
cp daisho_parser.cpython-*.so ..
cd ..
