import sys
from clang import cindex

def verbose(*args, **kwargs):
    '''filter predicate for show_ast: show all'''
    return True
def no_system_includes(cursor, level):
    '''filter predicate for show_ast: filter out verbose stuff from system include files'''
    return (level!= 1) or (cursor.location.file is not None and not cursor.location.file.name.startswith('/usr/include'))

# A function show(level, *args) would have been simpler but less fun
# and you'd need a separate parameter for the AST walkers if you want it to be exchangeable.
class Level(int):
    '''represent currently visited level of a tree'''
    def show(self, *args):
        '''pretty print an indented line'''
        print('\t'*self + ' '.join(map(str, args)))
    def __add__(self, inc):
        '''increase level'''
        return Level(super(Level, self).__add__(inc))

def is_valid_type(t):
    '''used to check if a cursor has a type'''
    return t.kind.value != 0
    
def qualifiers(t):
    '''set of qualifiers of a type'''
    q = set()
    if t.is_const_qualified(): q.add('const')
    if t.is_volatile_qualified(): q.add('volatile')
    if t.is_restrict_qualified(): q.add('restrict')
    return q

def show_type(t, level, title):
    '''pretty print type AST'''
    level.show(title, str(t.kind), ' '.join(qualifiers(t)))
    if is_valid_type(t.get_pointee()):
        show_type(t.get_pointee(), level+1, 'points to:')

def show_ast(cursor, filter_pred=verbose, level=Level()):
    '''pretty print cursor AST'''
    if filter_pred(cursor, level):
        level.show(cursor.kind, cursor.spelling, cursor.displayname, cursor.location)
        if is_valid_type(cursor.type):
            show_type(cursor.type, level+1, 'type:')
            show_type(cursor.type.get_canonical(), level+1, 'canonical type:')
        for c in cursor.get_children():
            show_ast(c, filter_pred, level+1)

if __name__ == '__main__':
    # configure python-clang to use the local clang library
    try:
        from ctypes.util import find_library
        # debug for python-haystack travis-ci
        for version in ["libclang", "clang", "clang-6.0", "clang-5.0", "clang-4.0", "clang-3.9", "clang-3.8", "clang-3.7"]:
            if find_library(version) is not None:
                cindex.Config.set_library_file(find_library(version))
                break
    except ImportError as e:
        print(e)
    
    from clang.cindex import TranslationUnit
    tu_options = TranslationUnit.PARSE_SKIP_FUNCTION_BODIES
    tu_options |= TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
    tu_options |= TranslationUnit.PARSE_INCLUDE_BRIEF_COMMENTS_IN_CODE_COMPLETION
    
    index = cindex.Index.create()
    tu = index.parse(sys.argv[1], options=tu_options)
    print('Translation unit:', tu.spelling)
    for f in tu.get_includes():
        print('\t'*f.depth, f.include.name)

    for diag in tu.diagnostics:
        print(f'{diag.severity}: {diag.spelling}')
        print(f'Location: {diag.location.file}:{diag.location.line}:{diag.location.column}')
        print(f'Options: {diag.option}')
        print(f'Category: {diag.category_name}')
        print('---')

    #show_ast(tu.cursor)
