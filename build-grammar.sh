./clean-grammar.sh
cd src/antlr

# Export required classpath
export CLASSPATH=".:/usr/local/lib/antlr4-complete.jar:$CLASSPATH"

# Compile the grammar
java -Xmx500M -cp "/usr/local/lib/antlr4-complete.jar:$CLASSPATH" org.antlr.v4.Tool StiltsParser.g4 StiltsLexer.g4 -Dlanguage=Cpp
rm *.tokens *.interp


#f1="StiltsLexer.java"
#f2="StiltsParser.java"
#f3="StiltsParserBaseListener.java"
#f4="StiltsParserListener.java"
# echo -e 'package antlr;\n' | cat - $f1  > temp && mv temp $f1
# echo -e 'package antlr;\n' | cat - $f2  > temp && mv temp $f2
# echo -e 'package antlr;\n' | cat - $f3  > temp && mv temp $f3
# echo -e 'package antlr;\n' | cat - $f4  > temp && mv temp $f4
#rm temp 2>/dev/null

# Move the files into a new build directory
mkdir ../antlr-generated/ 2>/dev/null
mv StiltsLexer.cpp StiltsLexer.h StiltsParser.cpp StiltsParser.h StiltsParserBaseListener.cpp StiltsParserBaseListener.h StiltsParserListener.cpp StiltsParserListener.h ../antlr-generated 2>/dev/null
cd ../antlr-generated/

# Build the lexer and parser

FLAGS="-Iantlr-generated/"
FLAGS="${FLAGS} -I/usr/local/include/antlr4-runtime/"
FLAGS="${FLAGS} -L/usr/local/lib/libantlr4-runtime/"

if [ $1 ] && [ $1 = "release" ]; then
  FLAGS="${FLAGS} -O3 -march=native"
else
  FLAGS="${FLAGS} -O0 -g -fsanitize=address"
fi

#echo "Compiling grammar with flags: $FLAGS"
c++ $FLAGS -c *.cpp

#export CLASSPATH=".:/usr/local/lib/antlr4-complete.jar:$CLASSPATH"
#javac *.java

