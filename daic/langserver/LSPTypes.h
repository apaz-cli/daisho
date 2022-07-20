
// #include <daisho/Daisho.h>

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"

///////////////////
// BASE PROTOCOL //
///////////////////

enum LSPType {
    LSP_ANY_OBJECT = cJSON_Object,
    LSP_ANY_ARRAY = cJSON_Array,
    LSP_ANY_STRING = cJSON_String,
    LSP_ANY_NULL = cJSON_NULL,
    LSP_ANY_INT,
    LSP_ANY_UINT,
    LSP_ANY_DECIMAL,
    LSP_ANY_BOOLEAN,
};

typedef void* LSPNull;
typedef int32_t LSPInteger;
typedef uint32_t LSPUInteger;
typedef double LSPDecimal;
typedef char* LSPString;
typedef int LSPBool;

union LSPAny;
typedef union LSPAny LSPAny;
typedef LSPAny LSP_ProgressToken; /* integer | string */

typedef struct {
    LSPAny* buf;
    size_t len;
} LSPAny_Array;

typedef struct {
    LSPString* key;
    LSPAny* value;
} LSPObjectEntry;

typedef struct {
    LSPObjectEntry* entries;
    size_t len;
    size_t cap;
} LSPObject;

typedef struct {
    LSPAny** items;
    size_t len;
    size_t cap;
} LSPArray;

union LSPAny {
    struct {
        void* as_null;
        LSPObject* as_object;
        LSPArray* as_array;
        LSPString* as_str;
        LSPInteger* as_int;
        LSPUInteger* as_uint;
        LSPDecimal* as_decimal;
    };
    unsigned char label;
};

typedef struct {
    LSPString* jsonrpc;
    LSPAny id; /* Int or Str */
    LSPString* method;
    LSPArray* params; /* Nullable */
} LSP_RequestMessage;

typedef struct {
    LSPInteger* code;
    LSPString* message;
    LSPAny data; /* string | number | boolean | array | object | null */
} LSP_ResponseError;

typedef struct {
    LSPString* jsonrpc;
    LSPAny id;                /* integer | string | null */
    LSPAny* result;           /* string | number | boolean | object | null */
    LSP_ResponseError* error; /* Nullable */
} LSP_ResponseMessage;

#define JSONRPC_ERROR_CODE_PARSEERROR -32700
#define JSONRPC_ERROR_CODE_INVALIDREQUEST -32600
#define JSONRPC_ERROR_CODE_METHODNOTFOUND -32601
#define JSONRPC_ERROR_CODE_INVALIDPARAMS -32602
#define JSONRPC_ERROR_CODE_INTERNALERROR -32603
#define JSONRPC_RESERVED_ERROR_RANGE_START -32099
#define JSONRPC_ERROR_CODE_SERVERNOTINITIALIZED -32002
#define JSONRPC_ERROR_CODE_UNKNOWNERRORCODE -32001
#define JSONRPC_RESERVED_ERROR_RANGE_END -32000
#define LSP_RESERVED_ERROR_RANGE_START -32899
#define LSP_ERROR_CODE_REQUESTFAILED -32803
#define LSP_ERROR_CODE_SERVERCANCELLED -32802
#define LSP_ERROR_CODE_CONTENTMODIFIED -32801
#define LSP_ERROR_CODE_REQUESTCANCELLED -32800
#define LSP_RESERVED_ERROR_RANGE_END -32800

typedef struct {
    LSPString* jsonrpc;
    LSPString* method;
    LSPAny* params; /* Nullable, array | object */
} LSP_NotificationMessage;

typedef struct {
    LSPAny* params; /* integer | string */
} LSP_CancelParams;

typedef struct {
    LSP_ProgressToken* token;
    void* value;
} LSP_ProgressParams;

//////////////////////////////
// LANGUAGE SERVER PROTOCOL //
//////////////////////////////

typedef struct {
    LSPString* textDocument; /* The text document's URI in string form */
    struct {
        LSPUInteger line;
        LSPUInteger character;
    } position;
} LSPHoverParams;

typedef struct {
    LSPString* value; /* Nullable? Error in protocol? */
} LSPHoverResult;

typedef LSPString LSP_DocumentURI;
typedef LSPString LSPURI;

typedef struct {
    LSPBool* applyEdit;
} LSPClientCapabilities;

static char const* const LSPEOLs[] = {"\n", "\r\n", "\r", NULL};

typedef struct {
    LSPUInteger* line;
    LSPUInteger* character;
} LSP_Position;

typedef LSPString LSPPositionEncodingKind;

#define LSPPositionEncodingKind_UTF8 "utf-8"
#define LSPPositionEncodingKind_UTF16 "utf-16"
#define LSPPositionEncodingKind_UTF32 "utf-32"

typedef struct {
    LSP_Position* start;
    LSP_Position* end;
} LSP_Range;

typedef struct {
    LSP_DocumentURI* uri;
    LSPString* languageId;
    LSPInteger* version;  // Increases after each change, including undo/redo.
    LSPString* text;
} LSP_TextDocumentItem;

typedef struct {
    LSP_DocumentURI* uri;
} LSP_TextDocumentIdentifier;

typedef struct {
    LSP_TextDocumentIdentifier super;
    LSPInteger* version;
} LSP_VersionedTextDocumentIdentifier;

typedef struct {
    LSP_TextDocumentIdentifier super;
    LSPInteger* version;  // Nullable
} LSP_OptionalVersionedTextDocumentIdentifier;

typedef struct {
    LSP_TextDocumentIdentifier* textDocument;
    LSP_Position* position;
} LSP_TextDocumentPositionParams;

typedef struct {
    LSPString* language;  // Nullable
    LSPString* scheme;    // Nullable
    LSPString* pattern;   // Nullable, Glob pattern.
} LSP_DocumentFilter;

typedef struct {
    LSP_DocumentFilter* filters;
    size_t len;
} LSP_DocumentSelector;

typedef struct {
    LSP_Range* range;
    LSPString* newText;
} LSP_TextEdit;

typedef struct {
    LSPString* label;
    LSPBool* needsConfirmation;  // Nullable
    LSPString* description;      // Nullable
} LSP_ChangeAnnotation;

typedef LSPString LSP_ChangeAnnotationIdentifier;

typedef struct {
    LSP_TextEdit super;
    LSP_ChangeAnnotationIdentifier* annotationId;
} LSP_AnnotatedTextEdit;

typedef struct {
    LSP_AnnotatedTextEdit edits;  // Allow annotationId to be nullable here.
    size_t len;
} LSP_TextEditArray;

typedef struct {
    LSP_OptionalVersionedTextDocumentIdentifier* textDocument;
    LSP_TextEditArray* edits;
} LSP_TextDocumentEdit;

typedef struct {
    LSP_DocumentURI* uri;
    LSP_Range* range;
} LSP_Location;

typedef struct {
    LSP_Range* originSelectionRange;  // Nullable,
    LSP_DocumentURI* targetUri;
    LSP_Range* targetRange;
    LSP_Range* targetSelectionRange;
} LSP_LocationLink;

typedef enum {
    LSP_DIAGNOSTICSEVERITY_NULL = 0,
    LSP_DIAGNOSTICSEVERITY_ERROR = 1,
    LSP_DIAGNOSTICSEVERITY_WARNING = 2,
    LSP_DIAGNOSTICSEVERITY_INFORMATION = 3,
    LSP_DIAGNOSTICSEVERITY_HINT = 4,
} LSP_DiagnosticSeverity;

typedef struct {
    LSP_DocumentURI href;
} LSP_CodeDescription;

typedef enum {
    LSP_DIAGNOSTICTAG_UNNECESSARY = 1,
    LSP_DIAGNOSTICTAG_DEPRECATED = 2,
} LSP_DiagnosticTag;

typedef struct {
    LSP_DiagnosticTag* buf;
    size_t len;
} LSP_DiagnosticTagArray;

typedef struct {
    LSP_Location* location;
    LSPString* message;
} LSP_DiagnosticRelatedInformation;

typedef struct {
    LSP_Range* range;
    LSP_DiagnosticSeverity severity;   // Nullable as 0
    LSPAny* code;                      // Nullable, integer | string
    LSP_CodeDescription* description;  // Nullable
    LSPString* source;                 // Nullable
    LSPString* message;
    LSP_DiagnosticTagArray* tags;  // Nullable
    LSPAny* data;                  // Nullable
} LSP_Diagnostic;

typedef struct {
    LSPString* title;
    LSPString* command;
    LSPAny_Array* arguments;  // Nullable
} LSP_Command;

typedef char* LSP_MarkupKind;
#define LSP_MARKUPKIND_PLAINTEXT "plaintext"
#define LSP_MARKUPKIND_MARKDOWN "markdown"

typedef struct {
    LSP_MarkupKind kind;
    LSPString* value;
} LSP_MarkupContent;

