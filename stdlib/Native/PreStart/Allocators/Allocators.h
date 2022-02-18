#ifndef __DAI_STDLIB_ALLOCATORS
#define __DAI_STDLIB_ALLOCATORS

/*
 * Allocator API:
 * Constructor takes a slice of memory to chunk up.
 * Allocator returns a slice of memory (with size).
 * Allocator frees a slice of memory (with size) (or does nothing).
 *
 * This greatly simplifies the implementation of the bump and masked allocators.
 */

/* The genericity of the allocators will be managed by a wrapper in Daisho, not in this C code.
   These allocators are not fully implemented in Daisho to make implementing daic easier. */

#include "AllocUtil.h"
#include "BumpAllocator.h"
#include "Mallocator.h"
#include "MaskedAllocator.h"

#endif /* __DAI_STDLIB_ALLOCATORS */
