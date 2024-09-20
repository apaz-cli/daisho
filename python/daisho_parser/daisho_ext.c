#define PY_SSIZE_T_CLEAN


#if __has_include(<Python.h>)
#include <Python.h>
#else
#include <python3.11/Python.h> // linter
#endif

#include <stdint.h>
#include <stdio.h>

#include "daisho.h"

_Static_assert(sizeof(int32_t) == sizeof(int), "int32_t is not int");

static PyObject *ast_to_python_dict(daisho_astnode_t *node) {
  if (!node)
    Py_RETURN_NONE;

  // Create a Python dictionary to hold the AST node data
  PyObject *dict = PyDict_New();
  if (!dict)
    return NULL;

  // Add kind to the dictionary
  const char *kind_str = daisho_nodekind_name[node->kind];
  PyObject *kind = PyUnicode_InternFromString(kind_str);
  if (!kind) {
    Py_DECREF(dict);
    return NULL;
  }
  PyDict_SetItemString(dict, "kind", kind);
  Py_DECREF(kind);

  // Convert codepoint array to Python string
  PyObject *tok_repr_str = PyUnicode_FromKindAndData(
      PyUnicode_4BYTE_KIND, node->tok_repr, (ssize_t)node->repr_len);
  if (!tok_repr_str) {
    Py_DECREF(dict);
    return NULL;
  }
  PyDict_SetItemString(dict, "tok_repr", tok_repr_str);
  Py_DECREF(tok_repr_str);

  // Add children to the dictionary
  PyObject *children_list = PyList_New(node->num_children);
  if (!children_list) {
    Py_DECREF(dict);
    return NULL;
  }
  for (uint16_t i = 0; i < node->num_children; i++) {
    PyObject *child = ast_to_python_dict(node->children[i]);
    if (!child) {
      Py_DECREF(children_list);
      Py_DECREF(dict);
      return NULL;
    }
    PyList_SetItem(children_list, (Py_ssize_t)i, child);
  }
  PyDict_SetItemString(dict, "children", children_list);
  Py_DECREF(children_list);

  // TODO: Add other items to the node. Extension point.

  return dict;
}

static PyObject *daisho_ext_parse_program(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_program(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_namespace(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_namespace(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_topdecl(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_topdecl(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_structdecl(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_structdecl(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_uniondecl(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_uniondecl(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_traitdecl(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_traitdecl(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_impldecl(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_impldecl(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_ctypedecl(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_ctypedecl(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_cfndecl(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_cfndecl(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_fndecl(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_fndecl(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_fnproto(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_fnproto(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_fnkw(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_fnkw(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_fnmember(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_fnmember(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_stunmembers(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_stunmembers(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_trimmembers(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_trimmembers(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_varmembers(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_varmembers(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_tmplexpand(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_tmplexpand(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_kdim(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_kdim(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_kexpand(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_kexpand(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_returntype(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_returntype(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_type(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_type(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_fntype(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_fntype(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_ptrtype(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_ptrtype(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_basetype(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_basetype(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_tupletype(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_tupletype(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_voidptr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_voidptr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_typelist(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_typelist(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_exprlist(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_exprlist(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_fnarg(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_fnarg(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_arglist(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_arglist(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_protoarg(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_protoarg(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_protoarglist(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_protoarglist(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_expr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_expr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_preretexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_preretexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_forexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_forexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_whileexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_whileexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_preifexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_preifexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_ternexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_ternexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_thenexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_thenexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_alsoexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_alsoexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_ceqexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_ceqexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_logorexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_logorexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_logandexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_logandexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_binorexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_binorexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_binxorexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_binxorexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_binandexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_binandexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_deneqexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_deneqexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_cmpexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_cmpexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_shfexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_shfexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_sumexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_sumexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_multexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_multexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_accexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_accexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_dotexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_dotexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_refexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_refexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_castexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_castexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_callexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_callexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_increxpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_increxpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_notexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_notexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_atomexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_atomexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_blockexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_blockexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_nsexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_nsexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_lambdaexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_lambdaexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_listcomp(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_listcomp(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_parenexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_parenexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_listlit(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_listlit(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_tuplelit(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_tuplelit(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_vardeclexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_vardeclexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_strlit(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_strlit(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_sstrlit(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_sstrlit(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_fstrlit(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_fstrlit(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_fstrfrag(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_fstrfrag(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_sizeofexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_sizeofexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_number(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_number(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_nativeexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_nativeexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_cident(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_cident(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_bsl(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_bsl(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_bsr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_bsr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_semiornl(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_semiornl(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_overloadable(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_overloadable(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_noexpr(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_noexpr(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_wcomma(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_wcomma(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_nocomma(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_nocomma(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_wsemi(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_wsemi(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_nosemi(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_nosemi(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyObject *daisho_ext_parse_wsemiornl(PyObject *self, PyObject *args) {

  // Extract args
  const char *input_str;
  size_t input_len;
  if (!PyArg_ParseTuple(args, "s#", &input_str, &input_len)) {
    return NULL;
  }

  // Convert input string to UTF-32 codepoints
  codepoint_t *cps = NULL;
  size_t cpslen = 0;
  if (!UTF8_decode((char *)input_str, input_len, &cps, &cpslen)) {
    PyErr_SetString(PyExc_RuntimeError, "Could not decode to UTF32.");
    return NULL;
  }

  // Initialize tokenizer
  daisho_tokenizer tokenizer;
  daisho_tokenizer_init(&tokenizer, cps, cpslen);

  // Token list
  static const size_t initial_cap = 4096 * 8;
  struct {
    daisho_token *buf;
    size_t size;
    size_t cap;
  } toklist = {(daisho_token *)malloc(sizeof(daisho_token) * initial_cap), 0, initial_cap};
  if (!toklist.buf) {
    free(cps);
    PyErr_SetString(PyExc_RuntimeError, "Out of memory allocating token list.");
    return NULL;
  }

  // Parse tokens
  daisho_token tok;
  do {
    tok = daisho_nextToken(&tokenizer);
    if (!(tok.kind == DAISHO_TOK_STREAMEND || tok.kind == DAISHO_TOK_WS || tok.kind == DAISHO_TOK_MLCOM || tok.kind == DAISHO_TOK_SLCOM)) {
      if (toklist.size == toklist.cap) {
        toklist.buf = realloc(toklist.buf, toklist.cap *= 2);
        if (!toklist.buf) {
          free(cps);
          PyErr_SetString(PyExc_RuntimeError,
                          "Out of memory reallocating token list.");
          return NULL;
        }
      }
      toklist.buf[toklist.size++] = tok;
    }
  } while (tok.kind != DAISHO_TOK_STREAMEND);

  // Initialize parser
  pgen_allocator allocator = pgen_allocator_new();
  daisho_parser_ctx parser;
  daisho_parser_ctx_init(&parser, &allocator, toklist.buf, toklist.size);

  // Parse AST
  daisho_astnode_t *ast = daisho_parse_wsemiornl(&parser);

  // Create result dictionary
  PyObject *result_dict = PyDict_New();
  if (!result_dict) {
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }

  // Convert AST to Python dictionary
  PyObject *ast_dict = ast_to_python_dict(ast);
  PyDict_SetItemString(result_dict, "ast", ast_dict ? ast_dict : Py_None);
  Py_XDECREF(ast_dict);

  // Create error list
  PyObject *error_list = PyList_New((Py_ssize_t)parser.num_errors);
  if (!error_list) {
    Py_DECREF(result_dict);
    pgen_allocator_destroy(&allocator);
    free(toklist.buf);
    free(cps);
    return NULL;
  }
  char *err_sev_str[] = {"info", "warning", "error", "fatal"};
  for (size_t i = 0; i < parser.num_errors; i++) {
    daisho_parse_err error = parser.errlist[i];
    PyObject *error_dict = PyDict_New();
    if (!error_dict) {
      Py_DECREF(result_dict);
      Py_DECREF(error_list);
      pgen_allocator_destroy(&allocator);
      free(toklist.buf);
      free(cps);
      return NULL;
    }

    // Set error info
    PyDict_SetItemString(error_dict, "msg", PyUnicode_FromString(error.msg));
    PyDict_SetItemString(
        error_dict, "severity",
        PyUnicode_InternFromString(err_sev_str[error.severity]));
    PyDict_SetItemString(error_dict, "line", PyLong_FromSize_t(error.line));
    PyDict_SetItemString(error_dict, "col", PyLong_FromSize_t(error.col));
    PyList_SetItem(error_list, (Py_ssize_t)i, error_dict);
  }
  PyDict_SetItemString(result_dict, "error_list", error_list);
  Py_DECREF(error_list);

  // Clean up
  pgen_allocator_destroy(&allocator);
  free(toklist.buf);
  free(cps);

  return result_dict;
}

static PyMethodDef daisho_methods[] = {
    {"parse_program", daisho_ext_parse_program, METH_VARARGS, "Parse a program and return the AST."},
    {"parse_namespace", daisho_ext_parse_namespace, METH_VARARGS, "Parse a namespace and return the AST."},
    {"parse_topdecl", daisho_ext_parse_topdecl, METH_VARARGS, "Parse a topdecl and return the AST."},
    {"parse_structdecl", daisho_ext_parse_structdecl, METH_VARARGS, "Parse a structdecl and return the AST."},
    {"parse_uniondecl", daisho_ext_parse_uniondecl, METH_VARARGS, "Parse a uniondecl and return the AST."},
    {"parse_traitdecl", daisho_ext_parse_traitdecl, METH_VARARGS, "Parse a traitdecl and return the AST."},
    {"parse_impldecl", daisho_ext_parse_impldecl, METH_VARARGS, "Parse a impldecl and return the AST."},
    {"parse_ctypedecl", daisho_ext_parse_ctypedecl, METH_VARARGS, "Parse a ctypedecl and return the AST."},
    {"parse_cfndecl", daisho_ext_parse_cfndecl, METH_VARARGS, "Parse a cfndecl and return the AST."},
    {"parse_fndecl", daisho_ext_parse_fndecl, METH_VARARGS, "Parse a fndecl and return the AST."},
    {"parse_fnproto", daisho_ext_parse_fnproto, METH_VARARGS, "Parse a fnproto and return the AST."},
    {"parse_fnkw", daisho_ext_parse_fnkw, METH_VARARGS, "Parse a fnkw and return the AST."},
    {"parse_fnmember", daisho_ext_parse_fnmember, METH_VARARGS, "Parse a fnmember and return the AST."},
    {"parse_stunmembers", daisho_ext_parse_stunmembers, METH_VARARGS, "Parse a stunmembers and return the AST."},
    {"parse_trimmembers", daisho_ext_parse_trimmembers, METH_VARARGS, "Parse a trimmembers and return the AST."},
    {"parse_varmembers", daisho_ext_parse_varmembers, METH_VARARGS, "Parse a varmembers and return the AST."},
    {"parse_tmplexpand", daisho_ext_parse_tmplexpand, METH_VARARGS, "Parse a tmplexpand and return the AST."},
    {"parse_kdim", daisho_ext_parse_kdim, METH_VARARGS, "Parse a kdim and return the AST."},
    {"parse_kexpand", daisho_ext_parse_kexpand, METH_VARARGS, "Parse a kexpand and return the AST."},
    {"parse_returntype", daisho_ext_parse_returntype, METH_VARARGS, "Parse a returntype and return the AST."},
    {"parse_type", daisho_ext_parse_type, METH_VARARGS, "Parse a type and return the AST."},
    {"parse_fntype", daisho_ext_parse_fntype, METH_VARARGS, "Parse a fntype and return the AST."},
    {"parse_ptrtype", daisho_ext_parse_ptrtype, METH_VARARGS, "Parse a ptrtype and return the AST."},
    {"parse_basetype", daisho_ext_parse_basetype, METH_VARARGS, "Parse a basetype and return the AST."},
    {"parse_tupletype", daisho_ext_parse_tupletype, METH_VARARGS, "Parse a tupletype and return the AST."},
    {"parse_voidptr", daisho_ext_parse_voidptr, METH_VARARGS, "Parse a voidptr and return the AST."},
    {"parse_typelist", daisho_ext_parse_typelist, METH_VARARGS, "Parse a typelist and return the AST."},
    {"parse_exprlist", daisho_ext_parse_exprlist, METH_VARARGS, "Parse a exprlist and return the AST."},
    {"parse_fnarg", daisho_ext_parse_fnarg, METH_VARARGS, "Parse a fnarg and return the AST."},
    {"parse_arglist", daisho_ext_parse_arglist, METH_VARARGS, "Parse a arglist and return the AST."},
    {"parse_protoarg", daisho_ext_parse_protoarg, METH_VARARGS, "Parse a protoarg and return the AST."},
    {"parse_protoarglist", daisho_ext_parse_protoarglist, METH_VARARGS, "Parse a protoarglist and return the AST."},
    {"parse_expr", daisho_ext_parse_expr, METH_VARARGS, "Parse a expr and return the AST."},
    {"parse_preretexpr", daisho_ext_parse_preretexpr, METH_VARARGS, "Parse a preretexpr and return the AST."},
    {"parse_forexpr", daisho_ext_parse_forexpr, METH_VARARGS, "Parse a forexpr and return the AST."},
    {"parse_whileexpr", daisho_ext_parse_whileexpr, METH_VARARGS, "Parse a whileexpr and return the AST."},
    {"parse_preifexpr", daisho_ext_parse_preifexpr, METH_VARARGS, "Parse a preifexpr and return the AST."},
    {"parse_ternexpr", daisho_ext_parse_ternexpr, METH_VARARGS, "Parse a ternexpr and return the AST."},
    {"parse_thenexpr", daisho_ext_parse_thenexpr, METH_VARARGS, "Parse a thenexpr and return the AST."},
    {"parse_alsoexpr", daisho_ext_parse_alsoexpr, METH_VARARGS, "Parse a alsoexpr and return the AST."},
    {"parse_ceqexpr", daisho_ext_parse_ceqexpr, METH_VARARGS, "Parse a ceqexpr and return the AST."},
    {"parse_logorexpr", daisho_ext_parse_logorexpr, METH_VARARGS, "Parse a logorexpr and return the AST."},
    {"parse_logandexpr", daisho_ext_parse_logandexpr, METH_VARARGS, "Parse a logandexpr and return the AST."},
    {"parse_binorexpr", daisho_ext_parse_binorexpr, METH_VARARGS, "Parse a binorexpr and return the AST."},
    {"parse_binxorexpr", daisho_ext_parse_binxorexpr, METH_VARARGS, "Parse a binxorexpr and return the AST."},
    {"parse_binandexpr", daisho_ext_parse_binandexpr, METH_VARARGS, "Parse a binandexpr and return the AST."},
    {"parse_deneqexpr", daisho_ext_parse_deneqexpr, METH_VARARGS, "Parse a deneqexpr and return the AST."},
    {"parse_cmpexpr", daisho_ext_parse_cmpexpr, METH_VARARGS, "Parse a cmpexpr and return the AST."},
    {"parse_shfexpr", daisho_ext_parse_shfexpr, METH_VARARGS, "Parse a shfexpr and return the AST."},
    {"parse_sumexpr", daisho_ext_parse_sumexpr, METH_VARARGS, "Parse a sumexpr and return the AST."},
    {"parse_multexpr", daisho_ext_parse_multexpr, METH_VARARGS, "Parse a multexpr and return the AST."},
    {"parse_accexpr", daisho_ext_parse_accexpr, METH_VARARGS, "Parse a accexpr and return the AST."},
    {"parse_dotexpr", daisho_ext_parse_dotexpr, METH_VARARGS, "Parse a dotexpr and return the AST."},
    {"parse_refexpr", daisho_ext_parse_refexpr, METH_VARARGS, "Parse a refexpr and return the AST."},
    {"parse_castexpr", daisho_ext_parse_castexpr, METH_VARARGS, "Parse a castexpr and return the AST."},
    {"parse_callexpr", daisho_ext_parse_callexpr, METH_VARARGS, "Parse a callexpr and return the AST."},
    {"parse_increxpr", daisho_ext_parse_increxpr, METH_VARARGS, "Parse a increxpr and return the AST."},
    {"parse_notexpr", daisho_ext_parse_notexpr, METH_VARARGS, "Parse a notexpr and return the AST."},
    {"parse_atomexpr", daisho_ext_parse_atomexpr, METH_VARARGS, "Parse a atomexpr and return the AST."},
    {"parse_blockexpr", daisho_ext_parse_blockexpr, METH_VARARGS, "Parse a blockexpr and return the AST."},
    {"parse_nsexpr", daisho_ext_parse_nsexpr, METH_VARARGS, "Parse a nsexpr and return the AST."},
    {"parse_lambdaexpr", daisho_ext_parse_lambdaexpr, METH_VARARGS, "Parse a lambdaexpr and return the AST."},
    {"parse_listcomp", daisho_ext_parse_listcomp, METH_VARARGS, "Parse a listcomp and return the AST."},
    {"parse_parenexpr", daisho_ext_parse_parenexpr, METH_VARARGS, "Parse a parenexpr and return the AST."},
    {"parse_listlit", daisho_ext_parse_listlit, METH_VARARGS, "Parse a listlit and return the AST."},
    {"parse_tuplelit", daisho_ext_parse_tuplelit, METH_VARARGS, "Parse a tuplelit and return the AST."},
    {"parse_vardeclexpr", daisho_ext_parse_vardeclexpr, METH_VARARGS, "Parse a vardeclexpr and return the AST."},
    {"parse_strlit", daisho_ext_parse_strlit, METH_VARARGS, "Parse a strlit and return the AST."},
    {"parse_sstrlit", daisho_ext_parse_sstrlit, METH_VARARGS, "Parse a sstrlit and return the AST."},
    {"parse_fstrlit", daisho_ext_parse_fstrlit, METH_VARARGS, "Parse a fstrlit and return the AST."},
    {"parse_fstrfrag", daisho_ext_parse_fstrfrag, METH_VARARGS, "Parse a fstrfrag and return the AST."},
    {"parse_sizeofexpr", daisho_ext_parse_sizeofexpr, METH_VARARGS, "Parse a sizeofexpr and return the AST."},
    {"parse_number", daisho_ext_parse_number, METH_VARARGS, "Parse a number and return the AST."},
    {"parse_nativeexpr", daisho_ext_parse_nativeexpr, METH_VARARGS, "Parse a nativeexpr and return the AST."},
    {"parse_cident", daisho_ext_parse_cident, METH_VARARGS, "Parse a cident and return the AST."},
    {"parse_bsl", daisho_ext_parse_bsl, METH_VARARGS, "Parse a bsl and return the AST."},
    {"parse_bsr", daisho_ext_parse_bsr, METH_VARARGS, "Parse a bsr and return the AST."},
    {"parse_semiornl", daisho_ext_parse_semiornl, METH_VARARGS, "Parse a semiornl and return the AST."},
    {"parse_overloadable", daisho_ext_parse_overloadable, METH_VARARGS, "Parse a overloadable and return the AST."},
    {"parse_noexpr", daisho_ext_parse_noexpr, METH_VARARGS, "Parse a noexpr and return the AST."},
    {"parse_wcomma", daisho_ext_parse_wcomma, METH_VARARGS, "Parse a wcomma and return the AST."},
    {"parse_nocomma", daisho_ext_parse_nocomma, METH_VARARGS, "Parse a nocomma and return the AST."},
    {"parse_wsemi", daisho_ext_parse_wsemi, METH_VARARGS, "Parse a wsemi and return the AST."},
    {"parse_nosemi", daisho_ext_parse_nosemi, METH_VARARGS, "Parse a nosemi and return the AST."},
    {"parse_wsemiornl", daisho_ext_parse_wsemiornl, METH_VARARGS, "Parse a wsemiornl and return the AST."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef daishomodule = {PyModuleDef_HEAD_INIT, "daishoparser", NULL, -1, daisho_methods};

PyMODINIT_FUNC PyInit_daisho_parser(void) { return PyModule_Create(&daishomodule); }
