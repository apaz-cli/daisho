#pragma once
#ifndef __STILTS_STD_RUNTIME_INCLUDE
#define __STILTS_STD_RUNTIME_INCLUDE

/* The project is structured hierarchically like so. */

#include "Configs/StiltsConfigs.h"
#define __STILTS
#include "PreProcessor/StiltsPreprocessor.h"
#undef __STILTS
#include "PreStart/StiltsPreStart.h"
#define __STILTS
#include "Builtins/StiltsBuiltins.h"
#undef __STILTS

#endif /* __STILTS_STDLIB_INCLUDES */
