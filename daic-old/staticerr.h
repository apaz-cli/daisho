#ifndef DAIC_STATICERR_INCLUDE
#define DAIC_STATICERR_INCLUDE

///////////////////////////
// STATIC ERROR MESSAGES //
///////////////////////////

static char* daic_oom_err = "Out of memory.";

static char* daic_dne_err = "The file does not exist.";
static char* daic_open_err = "Could not open file.";
static char* daic_stat_err = "Could not stat file.";
static char* daic_eperm_err = "Permission denied.";
static char* daic_fnf_err = "Could not not find any files matching the include path.";
static char* daic_realpath_err = "Failed to resolve the path to the file with realpath().";
static char* daic_nohome_err =
    "Cannot expand \"~\" in include path when no $HOME environment variable is set.";

static char* daic_native_err = "Could not parse native body.";

static char* daic_incl_already_err = "Already included.";
static char* daic_incl_path_err = "Could not resolve inlcude path.";
static char* daic_incl_decode_err = "Failed to decode the include path to utf8.";

static char* daic_entire_file_err = "Could not parse the entire file.";

static char* daic_number_range_err = "Number out of range.";
static char* daic_number_parse_err = "Number could not be parsed.";

#endif /* DAIC_STATICERR_INCLUDE */
