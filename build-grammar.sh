./clean-grammar.sh
cd src/antlr

# Export required classpath
export CLASSPATH=".:/usr/local/lib/antlr4-complete.jar:$CLASSPATH"

# Compile the grammar
java -Xmx500M -cp "/usr/local/lib/antlr4-complete.jar:$CLASSPATH" org.antlr.v4.Tool StiltsParser.g4 StiltsLexer.g4 -Dlanguage=Cpp

f1="StiltsLexer.java"
f2="StiltsParser.java"
f3="StiltsParserBaseListener.java"
f4="StiltsParserListener.java"
# echo -e 'package antlr;\n' | cat - $f1  > temp && mv temp $f1
# echo -e 'package antlr;\n' | cat - $f2  > temp && mv temp $f2
# echo -e 'package antlr;\n' | cat - $f3  > temp && mv temp $f3
# echo -e 'package antlr;\n' | cat - $f4  > temp && mv temp $f4
rm temp 2>/dev/null

mkdir ../antlr-generated/ 2>/dev/null
mv *.class *.interp *.tokens StiltsLexer.java StiltsParser.java StiltsParserBaseListener.java StiltsParserListener.java StiltsLexer.cpp StiltsLexer.h StiltsParser.cpp StiltsParser.h StiltsParserBaseListener.cpp StiltsParserBaseListener.h StiltsParserListener.cpp StiltsParserListener.h ../antlr-generated 2>/dev/null

export CLASSPATH=".:/usr/local/lib/antlr4-complete.jar:$CLASSPATH"
#javac *.java

