#pragma once
#ifndef __DAI_STD_RUNTIME_INCLUDE
#define __DAI_STD_RUNTIME_INCLUDE

/* The project is structured hierarchically like so. */

#include "Native/Configs/Configs.h"
#define __DAI
#include "Native/PreProcessor/PreProcessor.h"
#undef __DAI
#include "Native/PreStart/PreStart.h"
#define __DAI
#include "Native/Builtins/Builtins.h"
#undef __DAI

#endif /* __DAI_STDLIB_INCLUDES */
