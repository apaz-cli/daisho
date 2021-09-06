#!/bin/sh

FLAGS="-Iantlr-generated/"
FLAGS="${FLAGS} -I/usr/local/include/antlr4-runtime/"
FLAGS="${FLAGS} -L/usr/local/lib/libantlr4-runtime/"
FLAGS="${FLAGS} -I./antlr-generated/"
if [ $1 ] && [ $1 = "release" ]; then
  FLAGS="${FLAGS} -O3 -flto -march=native"
else
  FLAGS="${FLAGS} -O0 -g -fsanitize=address"
fi

OBJECTS=""
OBJECTS="${OBJECTS}antlr-generated/StiltsLexer.o "
OBJECTS="${OBJECTS}antlr-generated/StiltsParser.o "
OBJECTS="${OBJECTS}antlr-generated/StiltsParserBaseListener.o "
OBJECTS="${OBJECTS}antlr-generated/StiltsParserListener.o"

ARCHIVES="/usr/local/lib/libantlr4-runtime.a"

#echo "Compiling stiltc with flags: $FLAGS"
#echo "Compiling stiltc with objects: $OBJECTS"
#echo "Compiling stiltc with archives: $ARCHIVES"

cd src/
c++ -c Compiler.cpp $FLAGS 
c++ Compiler.o $OBJECTS $ARCHIVES $FLAGS 

rm Compiler.o
sudo mv a.out /usr/bin/stiltc
