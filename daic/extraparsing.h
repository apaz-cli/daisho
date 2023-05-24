#ifndef DAIC_NATIVEPARSE_INCLUDE
#define DAIC_NATIVEPARSE_INCLUDE
#include <libgen.h>
#include <sys/stat.h>

#include "../stdlib/Daisho.h"
#include "allocator.h"
#include "daisho.peg.h"
#include "errhandler.h"
#include "list.h"
#include "utils.h"
#include "daic_context.h"

// typedef char* cstr;
// _DAIC_LIST_DECLARE(cstr)
// _DAIC_LIST_DEFINE(cstr)
_DAIC_LIST_DECLARE(codepoint_t)
_DAIC_LIST_DEFINE(codepoint_t)

_DAIC_LIST_DECLARE(daisho_token)
_DAIC_LIST_DEFINE(daisho_token)

static inline void
daic_allocator_cleanup(void* a) {
    pgen_allocator_destroy((pgen_allocator*)a);
}

static inline void
_Dai_String_cleanup(void* s) {
    _Dai_String_destroy(((_Dai_String*)s));
}

static inline void
printtok(daisho_token tok, FILE* f) {
    fprintf(f, "Token: (");
    for (size_t i = 0; i < tok.len; i++) {
        codepoint_t c = tok.content[i];
        if (c == '\n')
            fprintf(f, "\\n");
        else if (c == '\t')
            fprintf(f, "\\t");
        else if (c == '\r')
            fprintf(f, "\\r");
        else
            fputc(c, f);
    }

    fprintf(f, ") {.kind=%s, .len=%zu, .line=%zu, .col=%zu}\n", daisho_tokenkind_name[tok.kind],
            tok.len, tok.line, tok.col);
    fflush(f);
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

static inline char*
searchAbsoluteIncludePath(DaicContext* ctx, char* search, char** err_msg) {
    if (search[0] == '/') {
        return strdup(search);
    } else if (search[0] == '~') {
        static char* HOME = NULL;
        if (!HOME) {
            HOME = getenv("HOME");
            if (!HOME) {
                *err_msg = daic_nohome_err;
                return NULL;
            }
        }
        char* ret = joinpaths(HOME, "/", search + 1);
        if (!ret) daic_panic(ctx, daic_oom_err);
        return ret;
    }
    return NULL;
}

// Check if search exists in the folder that current_file is in.
static inline char*
searchLocalIncludePath(DaicContext* ctx, char* current_file, char* search) {
    char* dirn = dirname(current_file);
    if (!strcmp(dirn, ".")) return NULL;
    char* joined = joinpaths(dirn, "/", search);
    if (!joined) daic_panic(ctx, daic_oom_err);
    if (access(joined, F_OK) == -1) return free(joined), NULL;
    return joined;
}

// Check if search exists in the system include folder.
static inline char*
searchSystemIncludePath(DaicContext* ctx, char* search) {
    char* joined = joinpaths(_DAIC_LIB_INCLUDE_PATH, "/Daisho/", search);
    if (!joined) daic_panic(ctx, daic_oom_err);
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
searchIncludePath(DaicContext* ctx, char* current_file, char* search,
                  _Daic_List_InputFile* input_files, int local, char** err_msg) {
    // Don't search if starts with ~ or /
    char* ret = searchAbsoluteIncludePath(ctx, search, err_msg);
    if (*err_msg) return NULL;
    if (ret) return ret;

    // Cannonize the include path
    current_file = realpath(current_file, NULL);
    if (!current_file) {
        *err_msg = (errno == ENOENT) ? daic_dne_err : daic_realpath_err;
        return NULL;
    }

    // Look for the actual file.
    if (local) {
        ret = searchLocalIncludePath(ctx, current_file, search);
        if (!ret) ret = searchSystemIncludePath(ctx, search);
    } else {
        ret = searchSystemIncludePath(ctx, search);
        if (!ret) ret = searchLocalIncludePath(ctx, current_file, search);
    }

    // If the file cannot be found, error.
    if (!ret) {
        free(current_file);
        *err_msg = daic_fnf_err;
        return NULL;
    }

    // Cannonize the file found.
    char* real = realpath(ret, NULL);
    free(ret);
    free(current_file);
    if (!real) {
        *err_msg = (errno == ENOENT) ? daic_dne_err : daic_realpath_err;
        return NULL;
    }

    // Stat the file to get its inode.
    struct stat st;
    if (stat(real, &st) == -1) {
        free(real);
        *err_msg = daic_stat_err;
        return NULL;
    }
    ino_t real_inode = st.st_ino;

    // Use this inode to make sure we haven't opened this file already.
    // Return this as an error if we have.
    int already_found = 0;
    for (size_t i = 0; i < input_files->len; i++) {
        if (real_inode == input_files->buf[i].inode) {
            already_found = 1;
            break;
        }
    }
    if (already_found) {
        free(real);
        *err_msg = daic_incl_already_err;
        return NULL;
    }

    *err_msg = NULL;
    return real;
}

// To be called after an #include token is tokenized. Extracts the include path,
// Re-encodes it as UTF-8, then does path lookup. If that lookup is successful,
// (the file referenced exits), then the path is returned. If it's unsuccessful,
// or any previous step is unsuccessful, it's an error.
// The returned string must be freed with free().
// On success, err_msg is null and returns the include path to tokenize.
// On error, returns null and sets *err_msg.
static inline char*
parse_includePath(daisho_tokenizer* tctx, DaicContext* ctx, char* current_file,
                  _Daic_List_InputFile* input_files, char** err_msg) {
    parse_ws(tctx);

    _Daic_List_codepoint_t pathcps = _Daic_List_codepoint_t_new(ctx);

    daisho_token tok = daisho_nextToken(tctx);
    int isstr = tok.kind == DAISHO_TOK_STRLIT;
    int ispath = tok.kind == DAISHO_TOK_INCLUDEPATH;
    if (!(isstr | ispath)) {
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
            i++;  // skip to what the \ is escaping
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

    parse_ws(tctx);
    while (parse_current(tctx, ";")) {
        tctx->pos++;
        tctx->pos_col++;
        parse_ws(tctx);
    }

    char* retstr;
    size_t retlen;
    // Encode won't fail, it's valid because it was decoded earlier.
    if (!UTF8_encode(pathcps.buf, pathcps.len, &retstr, &retlen)) {
        *err_msg = daic_incl_decode_err;
        return NULL;
    }
    _Daic_List_codepoint_t_clear(&pathcps);

    char* foundstr = searchIncludePath(ctx, current_file, retstr, input_files, isstr, err_msg);
    UTF8_FREE(retstr);
    if (*err_msg) {
        free(foundstr);
        // err_msg is already set.
        return NULL;
    }

    *err_msg = NULL;
    return foundstr;
}

static inline InputFile
daic_read_utf8decode_file(char* path, char** err_msg) {
    InputFile of;
    of.fname = NULL;
    of.inode = 0;
    of.content = NULL;
    of.contentlen = 0;
    of.cps = NULL;
    of.cpslen = 0;
    of.cps_map = NULL;
    *err_msg = NULL;

    of.fname = realpath(path, NULL);
    if (!of.fname) {
        int e = errno;
        if (e == ENOENT)
            *err_msg = daic_dne_err;
        else if (e == EACCES)
            *err_msg = daic_eperm_err;
        else
            *err_msg = daic_realpath_err;
        return of;
    }

    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        *err_msg = daic_open_err;
        return of;
    }

    struct stat st;
    if (fstat(fd, &st)) {
        *err_msg = "Could not stat file.";
        return of;
    }
    of.contentlen = (size_t)st.st_size;
    of.inode = st.st_ino;

    of.content = (char*)malloc(of.contentlen + 1);
    if (!of.content) {
        *err_msg = "Could not allocate memory for the file's contents.";
        return of;
    }

    int err = 0;
    size_t bytes_read = _Dai_read_wrapper(fd, of.content, of.contentlen, &err);
    if (err) {
        *err_msg = "Could not read from the file.";
        return of;
    }

    if (!UTF8_decode_map(of.content, of.contentlen, &of.cps, &of.cpslen, &of.cps_map)) {
        *err_msg = "Could not decode to UTF32.";
        return of;
    }

    *err_msg = NULL;
    return of;
}

static inline DaicError*
daic_read_utf8decode_tokenize_file(DaicContext* ctx, char* inputFilePath,
                                   _Daic_List_daisho_token* append_tokens,
                                   _Daic_List_InputFile* opened_files, bool first_file) {
    char* read_err_msg = NULL;
    InputFile inf = daic_read_utf8decode_file(inputFilePath, &read_err_msg);
    if (read_err_msg) {
        char* emsg = NULL;
        size_t len = 0;
        size_t cap = 0;
        daic_cstring_appendf(&emsg, &len, &cap, "Could not read file %s: %s", inputFilePath,
                             read_err_msg);
        daic_cleanup_add(ctx, free, emsg);
        if (!emsg) emsg = read_err_msg;
        return daic_error_new(ctx, DAIC_ERROR_STAGE_TOKENIZER, read_err_msg, inputFilePath,
                              0 /*line*/, 0 /*col*/, _DAIC_ERROR_SEV_ERROR, 0 /*trace_frame*/);
    }

    // Jijack the finalizer uwu
    _Daic_List_InputFile_add(opened_files, inf);
    if (ctx->cleanup.len && ctx->cleanup.buf[ctx->cleanup.len-1].f == _Daic_List_InputFile_cleanup) {
        ctx->cleanup.len--;
    }

    daisho_tokenizer tokenizer;
    daisho_tokenizer_init(&tokenizer, inf.cps, inf.cpslen);

    int firsttoken = 1;
    daisho_token tok;
    do {
        tok = daisho_nextToken(&tokenizer);

        // Skip the shebang for included files.
        if (tok.kind == DAISHO_TOK_SHEBANG && !first_file && firsttoken) continue;
        firsttoken = 0;

        // Discard whitespace and end of stream, add other tokens to the list.
        if ((tok.kind == DAISHO_TOK_SLCOM) | (tok.kind == DAISHO_TOK_MLCOM) |
            (tok.kind == DAISHO_TOK_WS) | (tok.kind == DAISHO_TOK_STREAMEND))
            continue;

        if (tok.kind == DAISHO_TOK_NATIVE) {
            _Daic_List_daisho_token_add(append_tokens, tok);
            daisho_token last_tok = tok;

            tok = parse_Nativebody(&tokenizer);
            if (tok.kind == DAISHO_TOK_STREAMEND) {
                return daic_error_new(ctx, DAIC_ERROR_STAGE_TOKENIZER, daic_native_err,
                                      inputFilePath, last_tok.line /*line*/, last_tok.col /*col*/,
                                      _DAIC_ERROR_SEV_ERROR, 0 /*trace_frame*/);
            }
        }

        if (tok.kind == DAISHO_TOK_INCLUDE) {
            char* incl_errstr = NULL;
            char* inclpath =
                parse_includePath(&tokenizer, ctx, inputFilePath, opened_files, &incl_errstr);
            if (incl_errstr == daic_incl_already_err) continue;
            if (incl_errstr) {
                return daic_error_new(ctx, DAIC_ERROR_STAGE_TOKENIZER, incl_errstr, inputFilePath,
                                      tok.line /*line*/, tok.col /*col*/, _DAIC_ERROR_SEV_ERROR,
                                      0 /*trace_frame*/);
                fprintf(stderr,
                        "Error on line %zu of %s: \n"
                        "Reason: %s\n",
                        tokenizer.pos_line, inputFilePath, incl_errstr);
                free(inclpath);
                exit(1);
            }
            if (inclpath) {
                // Read, Decode, and Tokenize the included file.
                DaicError* incl_err = daic_read_utf8decode_tokenize_file(
                    ctx, inclpath, append_tokens, opened_files, 0);
                free(inclpath);
                if (incl_err) return incl_err;
            }
            free(inclpath);
            continue;
        }

        _Daic_List_daisho_token_add(append_tokens, tok);

    } while (tok.kind != DAISHO_TOK_STREAMEND);

    if (tokenizer.pos != tokenizer.len) {
        return daic_error_new(ctx, DAIC_ERROR_STAGE_TOKENIZER, daic_entire_file_err, inputFilePath,
                              0 /*line*/, 0 /*col*/, _DAIC_ERROR_SEV_ERROR, 0 /*trace_frame*/);
    }

    return NULL;
}

#endif /* DAIC_NATIVEPARSE_INCLUDE */
