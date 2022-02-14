#pragma once
#ifndef __DAI_STD_RUNTIME_INCLUDE
#define __DAI_STD_RUNTIME_INCLUDE

/* The project is structured hierarchically like so. */

#include "Native/Configs/DaishoConfigs.h"
#define __DAI
#include "Native/PreProcessor/DaishoPreprocessor.h"
#undef __DAI
#include "Native/PreStart/DaishoPreStart.h"
#define __DAI
#include "Native/Builtins/DaishoBuiltins.h"
#undef __DAI

#endif /* __DAI_STDLIB_INCLUDES */
