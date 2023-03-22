#ifndef DAIC_NATIVEPARSE_INCLUDE
#define DAIC_NATIVEPARSE_INCLUDE
#include <daisho/Daisho.h>
#include <libgen.h>
#include <sys/stat.h>

#include "allocator.h"
#include "daisho_peg.h"
#include "list.h"

// typedef char* cstr;
// _DAIC_LIST_DECLARE(cstr)
// _DAIC_LIST_DEFINE(cstr)
_DAIC_LIST_DECLARE(codepoint_t)
_DAIC_LIST_DEFINE(codepoint_t)

_DAIC_LIST_DECLARE(daisho_token)
_DAIC_LIST_DEFINE(daisho_token)

typedef struct {
    char* fname;
    ino_t inode;
    char* content;
    size_t contentlen;
    codepoint_t* cps;
    size_t cpslen;
} InputFile;

_DAIC_LIST_DECLARE(InputFile)
_DAIC_LIST_DEFINE(InputFile)

static inline void
InputFile_free(InputFile of) {
    if (of.fname) free(of.fname);
    if (of.content) free(of.content);
    if (of.cps) free(of.cps);
}

static inline void
printtok(daisho_token tok) {
    printf("Token: (");
    for (size_t i = 0; i < tok.len; i++) {
        codepoint_t c = tok.content[i];
        if (c == '\n')
            printf("\\n");
        else if (c == '\t')
            printf("\\t");
        else if (c == '\r')
            printf("\\r");
        else
            putchar(c);
    }

    printf(") {.kind=%s, .len=%zu, .line=%zu, .col=%zu}\n", daisho_tokenkind_name[tok.kind],
           tok.len, tok.line, tok.col);
    fflush(stdout);
}

static inline size_t
parse_current(daisho_tokenizer* ctx, char* s) {
    size_t len = strlen(s);
    if (!((ctx->len - ctx->pos) >= len)) return 0;

    size_t idx = ctx->pos;
    for (size_t i = 0; i < len; i++)
        if ((codepoint_t)s[i] != ctx->start[idx++]) return 0;

    return len;
}

static inline void
parse_ws(daisho_tokenizer* ctx) {
    while (true) {
        int cs = 0;
        codepoint_t c = ctx->start[ctx->pos];
        if ((c == ' ') | (c == '\r') | (c == '\t')) {
            cs = 1;
            ctx->pos++;
            ctx->pos_col++;
        } else if (c == '\n') {
            cs = 1;
            ctx->pos++;
            ctx->pos_line++;
            ctx->pos_col = 0;
        } else if (parse_current(ctx, "//")) {
            cs = 1;
            ctx->pos += 2;
            ctx->pos_col += 2;
            while ((ctx->pos != ctx->len) && ctx->start[ctx->pos] != '\n') {
                ctx->pos++;
                ctx->pos_col++;
            }
        } else if (parse_current(ctx, "/*")) {
            cs = 1;
            ctx->pos += 2;
            ctx->pos_col += 2;
            while (!parse_current(ctx, "*/")) {
                if (ctx->start[ctx->pos] == '\n') {
                    ctx->pos_line++;
                    ctx->pos_col = 0;
                } else {
                    ctx->pos_col++;
                }
                ctx->pos++;
            }
            size_t n = parse_current(ctx, "*/");
            ctx->pos_col += n;
            ctx->pos += n;
        }

        if (!cs) break;
    }
}

static inline daisho_token
parse_Nativebody(daisho_tokenizer* ctx) {
    parse_ws(ctx);
    size_t line = ctx->pos_line;
    size_t col = ctx->pos_col;
    size_t original_pos = ctx->pos;

    daisho_token failure;
    failure.kind = DAISHO_TOK_STREAMEND;
    failure.content = NULL;
    failure.len = 0;
    failure.line = line;
    failure.col = col;

    size_t depth = 1;
    size_t first = parse_current(ctx, "{");
    ctx->pos++;
    ctx->pos_col++;
    if (!first) return failure;

    while (depth && (ctx->pos <= ctx->len)) {
        codepoint_t c = ctx->start[ctx->pos];
        ctx->pos++;
        if (c == '{')
            depth++;
        else if (c == '}')
            depth--;

        if (c == '\n') {
            ctx->pos_col = 0;
            ctx->pos_line++;
        } else {
            ctx->pos_col++;
        }
    }

    if (depth) return failure;

    daisho_token capture;
    capture.kind = DAISHO_TOK_NATIVEBODY;
    capture.len = (ctx->pos - original_pos);      // Strip last }
    capture.content = ctx->start + original_pos;  // Strip first {
    capture.line = line;
    capture.col = col;
    return capture;
}

// Result must be freed.
static inline char*
joinpaths(char* folder, char* sep, char* file) {
    char* filename = (char*)malloc(strlen(folder) + strlen(sep) + strlen(file) + 1);
    strcpy(filename, folder);
    strcat(filename, sep);
    strcat(filename, file);
    return filename;
}

static char* incl_dne_err = "The file does not exist.";
static char* incl_fnf_err = "Could not not find any files matching the include path.";
static char* incl_realpath_err = "Failed to convert with realpath().";
static char* incl_home_err =
    "Cannot expand \"~\" in include path when no $HOME environment variable is set.";

static inline char*
searchAbsoluteIncludePath(char* search, char** err_msg) {
    if (search[0] == '/') {
        return strdup(search);
    } else if (search[0] == '~') {
        static char* HOME = NULL;
        if (!HOME) {
            HOME = getenv("HOME");
            if (!HOME) {
                *err_msg = incl_home_err;
                return NULL;
            }
        }
        return joinpaths(HOME, "/", search);
    }
    return NULL;
}

// Check if search exists in the folder that current_file is in.
static inline char*
searchLocalIncludePath(char* current_file, char* search) {
    char* dirn = dirname(current_file);
    if (!strcmp(dirn, ".")) return NULL;
    char* joined = joinpaths(dirn, "/", search);
    if (access(joined, F_OK) == -1) return free(joined), NULL;
    return joined;
}

// Check if search exists in the system include folder.
static inline char*
searchSystemIncludePath(char* search) {
    char* joined = joinpaths(_DAIC_LIB_INCLUDE_PATH, "/Daisho/", search);
    if (access(joined, F_OK) == -1) return free(joined), NULL;
    return joined;
}

// If the folder is an absolute path (starts with /), do no lookup.
// If the folder starts with ~, expand it and do no lookup (It's also absolute).
// If it was an #include <>, then search the system include path first, then
// files relative to the file being included from.
// If it was an #include "", search relative to the file being included from first,
// then the system include path.
// Finally, return the result of realpath().
// Sets err_msg on error.
static inline char*
searchIncludePath(char* current_file, char* search, int local, char** err_msg) {
    char* ret = searchAbsoluteIncludePath(search, err_msg);
    if (err_msg) return ret;

    if (!ret) {
        if (local) {
            ret = searchLocalIncludePath(current_file, search);
            if (!ret) ret = searchSystemIncludePath(search);
        } else {
            ret = searchSystemIncludePath(search);
            if (!ret) ret = searchLocalIncludePath(current_file, search);
        }
    }

    if (!ret) {
        *err_msg = incl_fnf_err;
        return NULL;
    }

    char* real = realpath(ret, NULL);
    if (!real) {
        if (errno == ENOENT) *err_msg = incl_dne_err;
        *err_msg = incl_realpath_err;
        return ret;
    } else {
        free(ret);
    }

    return *err_msg = NULL, real;
}

// To be called after an INCLUDE is tokenized.
// The returned string must be freed with UTF8_FREE.
// Returns null on error.
static inline char*
parse_includePath(daisho_tokenizer* ctx, char* current_file, char** err_msg) {
    parse_ws(ctx);

    _Daic_List_codepoint_t pathcps = _Daic_List_codepoint_t_new();

    daisho_token tok = daisho_nextToken(ctx);
    int isstr = tok.kind == DAISHO_TOK_STRLIT;
    int ispath = tok.kind == DAISHO_TOK_INCLUDEPATH;
    if (isstr | ispath) {
        *err_msg =
            "What followed #include/#import was not a valid "
            "string literal or include path token.";
        return NULL;
    }

    // We know that the token parsed, so we can
    // make structural assumptions.
    if (tok.len <= 2) {
        *err_msg = "Cannot include an empty string.";
        return NULL;
    }
    for (size_t i = 1; i < tok.len - 1; i++) {
        codepoint_t c = tok.content[i];
        if (c == '\\') {
            i++;
#define ADDESCAPE(un, esc) \
    if (c == un) _Daic_List_codepoint_t_add(&pathcps, esc);
            ADDESCAPE('n', '\n');
            ADDESCAPE('f', '\f');
            ADDESCAPE('b', '\b');
            ADDESCAPE('r', '\r');
            ADDESCAPE('t', '\t');
            ADDESCAPE('e', 27);
            ADDESCAPE('\\', '\\');
            ADDESCAPE('\'', '\'');
            ADDESCAPE('\"', '\"');
            ADDESCAPE('{', '{');
            ADDESCAPE('}', '}');
#undef ADDESCAPE
            i++;
        } else {
            _Daic_List_codepoint_t_add(&pathcps, c);
        }
    }

    char* retstr;
    size_t retlen;
    // Encode won't fail, it's valid because it was decoded earlier.
    UTF8_encode(pathcps.buf, pathcps.len, &retstr, &retlen);
    _Daic_List_codepoint_t_clear(&pathcps);

    char* foundstr = searchIncludePath(current_file, retstr, isstr, err_msg);
    UTF8_FREE(retstr);
    return foundstr;
}

static inline InputFile
daic_read_utf8decode_file(char* path, char** err_msg) {
    InputFile of;
    of.fname = strdup(path);
    of.inode = 0;
    of.content = NULL;
    of.contentlen = 0;
    of.cps = NULL;
    of.cpslen = 0;
    *err_msg = NULL;

    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        int e = errno;
        if (e == ENOENT) *err_msg = incl_dne_err;
        return of;
    }

    struct stat st;
    if (fstat(fd, &st)) {
        *err_msg = "Could not stat file.";
        return of;
    }
    of.contentlen = (size_t)st.st_size;
    of.inode = st.st_ino;

    of.content = _DAIC_MALLOC(of.contentlen + 1);
    if (!of.content) {
        *err_msg = "Could not allocate memory for the file's contents.";
        return of;
    }

    int err = 0;
    size_t bytes_read = _Dai_read_wrapper(fd, of.content, of.contentlen, &err);
    if (err) {
        *err_msg = "Could not read() from the file.";
        return of;
    }

    if (!UTF8_decode(of.content, of.contentlen, &of.cps, &of.cpslen)) {
        *err_msg = "Could not decode to UTF32.";
        return of;
    }

    return of;
}

static inline void
daic_read_utf8decode_tokenize_file(char* path, _Daic_List_InputFile* input_files,
                                   _Daic_List_daisho_token* append_tokens, int first_file) {
    char* err_msg = NULL;
    InputFile of = daic_read_utf8decode_file(path, &err_msg);
    if (err_msg || !of.cps) {
        fprintf(stderr, "%s", err_msg);
        exit(1);
    }
    _Daic_List_InputFile_add(input_files, of);

    daisho_tokenizer tokenizer;
    daisho_tokenizer_init(&tokenizer, of.cps, of.cpslen);

    int firsttoken = 1;
    daisho_token tok;
    do {
        tok = daisho_nextToken(&tokenizer);
        printtok(tok);
        fflush(stdout);

        // Skip the shebang for included files.
        if (tok.kind == DAISHO_TOK_SHEBANG && !first_file && firsttoken) continue;
        firsttoken = 0;

        // Discard whitespace and end of stream, add other tokens to the list.
        if ((tok.kind == DAISHO_TOK_SLCOM) | (tok.kind == DAISHO_TOK_MLCOM) |
            (tok.kind == DAISHO_TOK_WS) | (tok.kind == DAISHO_TOK_STREAMEND))
            continue;

        if (tok.kind == DAISHO_TOK_NATIVE) {
            _Daic_List_daisho_token_add(append_tokens, tok);
            tok = parse_Nativebody(&tokenizer);
            if (tok.kind == DAISHO_TOK_STREAMEND) {
                fprintf(stderr, "Error on line %zu of %s: Could not parse native body.\n",
                        tokenizer.pos_line, path);
                exit(1);
            }
        }

        if (tok.kind == DAISHO_TOK_INCLUDE) {
            char* incl_errstr = NULL;
            char* inclpath = parse_includePath(&tokenizer, path, &incl_errstr);
            if (incl_errstr || !inclpath) {
                fprintf(stderr,
                        "Error on line %zu of %s: Could not resolve include path.\n"
                        "Reason: %s\n",
                        tokenizer.pos_line, path, incl_errstr);
                exit(1);
            }

            daic_read_utf8decode_tokenize_file(inclpath, input_files, append_tokens, 0);
        }

        _Daic_List_daisho_token_add(append_tokens, tok);
    } while (tok.kind != DAISHO_TOK_STREAMEND);
}

#endif /* DAIC_NATIVEPARSE_INCLUDE */
