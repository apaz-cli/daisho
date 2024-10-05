import sys
import clang.cindex

def preprocess_file(filename):
    index = clang.cindex.Index.create()
    options = clang.cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
    tu = index.parse(filename, options=options)

    preprocessed_output = []
    for token in tu.get_tokens(extent=tu.cursor.extent):
        preprocessed_output.append(token.spelling)
    
    return preprocessed_output

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python preprocess.py <filename>")
        sys.exit(1)

    filename = sys.argv[1]
    preprocessed_code = preprocess_file(filename)
    print(preprocessed_code)
    print(clang.cindex.TokenKind._value_map)