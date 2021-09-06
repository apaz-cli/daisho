#!/bin/sh
cd /usr/local/include
sudo rm -r antlr4-common.h       BaseErrorListener.h     dfa                         LexerInterpreter.h           ProxyErrorListener.h     Token.h                  utf8.h            2>/dev/null
sudo rm -r antlr4-runtime.h      BufferedTokenStream.h   DiagnosticErrorListener.h   LexerNoViableAltException.h  RecognitionException.h   TokenSource.h            Vocabulary.h      2>/dev/null
sudo rm -r ANTLRErrorListener.h  CharStream.h            Exceptions.h                ListTokenSource.h            Recognizer.h             TokenStream.h            WritableToken.h   2>/dev/null
sudo rm -r ANTLRErrorStrategy.h  CommonTokenFactory.h    FailedPredicateException.h  misc                         RuleContext.h            TokenStreamRewriter.h                      2>/dev/null
sudo rm -r ANTLRFileStream.h     CommonToken.h           InputMismatchException.h    NoViableAltException.h       RuleContextWithAltNum.h  tree                                       2>/dev/null
sudo rm -r ANTLRInputStream.h    CommonTokenStream.h     InterpreterRuleContext.h    Parser.h                     RuntimeMetaData.h        UnbufferedCharStream.h                     2>/dev/null
sudo rm -r atn                   ConsoleErrorListener.h  IntStream.h                 ParserInterpreter.h          support                  UnbufferedTokenStream.h                    2>/dev/null
sudo rm -r BailErrorStrategy.h   DefaultErrorStrategy.h  Lexer.h                     ParserRuleContext.h          TokenFactory.h           utf8                                       2>/dev/null

cd /usr/local/lib
sudo rm    antlr4-complete.jar   libantlr4-runtime.a     libantlr4-runtime.so        libantlr4-runtime.so.4.9.2                                                                       2>/dev/null
