#pragma once
#ifndef __STILTS_STD_RUNTIME_INCLUDE
#define __STILTS_STD_RUNTIME_INCLUDE

/* The project is structured hierarchically like so. */

#include "Native/Configs/StiltsConfigs.h"
#define __STILTS
#include "Native/PreProcessor/StiltsPreprocessor.h"
#undef __STILTS
#include "Native/PreStart/StiltsPreStart.h"
#define __STILTS
#include "Native/Builtins/StiltsBuiltins.h"
#undef __STILTS

#endif /* __STILTS_STDLIB_INCLUDES */
