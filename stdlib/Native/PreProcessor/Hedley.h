/*
 * NOTE: I have made a lot of changes to this file (including renaming
 * all the macros), but no substantive changes. The library still
 * functions exactly the same. Although I've slapped the name of my
 * project onto it, full credit still goes to the developers of Hedley below.
 */

/* Changes:
 * 1. Replaced all instances of HEDLEY_ with _DAI_.
 *    This is to avoid introducing any identifiers not
 *    starting with _DAI_.
 * 2. Changed HEDLEY_MALLOC to _DAI_MALLOC_ATTR to
 *    avoid name clash with existing macro elsewhere.
 * 3. Renamed HEDLEY_VERSION to _DAI_HEDLEY_VERSION.
 */


 /* Hedley - https://nemequ.github.io/hedley
 * Created by Evan Nemerson <evan@nemerson.com>
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to
 * the public domain worldwide. This software is distributed without
 * any warranty.
 *
 * For details, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 * SPDX-License-Identifier: CC0-1.0
 */

#if !defined(_DAI_HEDLEY_VERSION) || (_DAI_HEDLEY_VERSION < 15)
#if defined(_DAI_HEDLEY_VERSION)
#  undef _DAI_HEDLEY_VERSION
#endif
#define _DAI_HEDLEY_VERSION 15

#if defined(_DAI_STRINGIFY_EX)
#  undef _DAI_STRINGIFY_EX
#endif
#define _DAI_STRINGIFY_EX(x) #x

#if defined(_DAI_STRINGIFY)
#  undef _DAI_STRINGIFY
#endif
#define _DAI_STRINGIFY(x) _DAI_STRINGIFY_EX(x)

#if defined(_DAI_CONCAT_EX)
#  undef _DAI_CONCAT_EX
#endif
#define _DAI_CONCAT_EX(a,b) a##b

#if defined(_DAI_CONCAT)
#  undef _DAI_CONCAT
#endif
#define _DAI_CONCAT(a,b) _DAI_CONCAT_EX(a,b)

#if defined(_DAI_CONCAT3_EX)
#  undef _DAI_CONCAT3_EX
#endif
#define _DAI_CONCAT3_EX(a,b,c) a##b##c

#if defined(_DAI_CONCAT3)
#  undef _DAI_CONCAT3
#endif
#define _DAI_CONCAT3(a,b,c) _DAI_CONCAT3_EX(a,b,c)

#if defined(_DAI_HEDLEY_VERSION_ENCODE)
#  undef _DAI_HEDLEY_VERSION_ENCODE
#endif
#define _DAI_HEDLEY_VERSION_ENCODE(major,minor,revision) (((major) * 1000000) + ((minor) * 1000) + (revision))

#if defined(_DAI_HEDLEY_VERSION_DECODE_MAJOR)
#  undef _DAI_HEDLEY_VERSION_DECODE_MAJOR
#endif
#define _DAI_HEDLEY_VERSION_DECODE_MAJOR(version) ((version) / 1000000)

#if defined(_DAI_HEDLEY_VERSION_DECODE_MINOR)
#  undef _DAI_HEDLEY_VERSION_DECODE_MINOR
#endif
#define _DAI_HEDLEY_VERSION_DECODE_MINOR(version) (((version) % 1000000) / 1000)

#if defined(_DAI_HEDLEY_VERSION_DECODE_REVISION)
#  undef _DAI_HEDLEY_VERSION_DECODE_REVISION
#endif
#define _DAI_HEDLEY_VERSION_DECODE_REVISION(version) ((version) % 1000)

#if defined(_DAI_GNUC_VERSION)
#  undef _DAI_GNUC_VERSION
#endif
#if defined(__GNUC__) && defined(__GNUC_PATCHLEVEL__)
#  define _DAI_GNUC_VERSION _DAI_HEDLEY_VERSION_ENCODE(__GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__)
#elif defined(__GNUC__)
#  define _DAI_GNUC_VERSION _DAI_HEDLEY_VERSION_ENCODE(__GNUC__, __GNUC_MINOR__, 0)
#endif

#if defined(_DAI_GNUC_VERSION_CHECK)
#  undef _DAI_GNUC_VERSION_CHECK
#endif
#if defined(_DAI_GNUC_VERSION)
#  define _DAI_GNUC_VERSION_CHECK(major,minor,patch) (_DAI_GNUC_VERSION >= _DAI_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
#  define _DAI_GNUC_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(_DAI_MSVC_VERSION)
#  undef _DAI_MSVC_VERSION
#endif
#if defined(_MSC_FULL_VER) && (_MSC_FULL_VER >= 140000000) && !defined(__ICL)
#  define _DAI_MSVC_VERSION _DAI_HEDLEY_VERSION_ENCODE(_MSC_FULL_VER / 10000000, (_MSC_FULL_VER % 10000000) / 100000, (_MSC_FULL_VER % 100000) / 100)
#elif defined(_MSC_FULL_VER) && !defined(__ICL)
#  define _DAI_MSVC_VERSION _DAI_HEDLEY_VERSION_ENCODE(_MSC_FULL_VER / 1000000, (_MSC_FULL_VER % 1000000) / 10000, (_MSC_FULL_VER % 10000) / 10)
#elif defined(_MSC_VER) && !defined(__ICL)
#  define _DAI_MSVC_VERSION _DAI_HEDLEY_VERSION_ENCODE(_MSC_VER / 100, _MSC_VER % 100, 0)
#endif

#if defined(_DAI_MSVC_VERSION_CHECK)
#  undef _DAI_MSVC_VERSION_CHECK
#endif
#if !defined(_DAI_MSVC_VERSION)
#  define _DAI_MSVC_VERSION_CHECK(major,minor,patch) (0)
#elif defined(_MSC_VER) && (_MSC_VER >= 1400)
#  define _DAI_MSVC_VERSION_CHECK(major,minor,patch) (_MSC_FULL_VER >= ((major * 10000000) + (minor * 100000) + (patch)))
#elif defined(_MSC_VER) && (_MSC_VER >= 1200)
#  define _DAI_MSVC_VERSION_CHECK(major,minor,patch) (_MSC_FULL_VER >= ((major * 1000000) + (minor * 10000) + (patch)))
#else
#  define _DAI_MSVC_VERSION_CHECK(major,minor,patch) (_MSC_VER >= ((major * 100) + (minor)))
#endif

#if defined(_DAI_INTEL_VERSION)
#  undef _DAI_INTEL_VERSION
#endif
#if defined(__INTEL_COMPILER) && defined(__INTEL_COMPILER_UPDATE) && !defined(__ICL)
#  define _DAI_INTEL_VERSION _DAI_HEDLEY_VERSION_ENCODE(__INTEL_COMPILER / 100, __INTEL_COMPILER % 100, __INTEL_COMPILER_UPDATE)
#elif defined(__INTEL_COMPILER) && !defined(__ICL)
#  define _DAI_INTEL_VERSION _DAI_HEDLEY_VERSION_ENCODE(__INTEL_COMPILER / 100, __INTEL_COMPILER % 100, 0)
#endif

#if defined(_DAI_INTEL_VERSION_CHECK)
#  undef _DAI_INTEL_VERSION_CHECK
#endif
#if defined(_DAI_INTEL_VERSION)
#  define _DAI_INTEL_VERSION_CHECK(major,minor,patch) (_DAI_INTEL_VERSION >= _DAI_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
#  define _DAI_INTEL_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(_DAI_INTEL_CL_VERSION)
#  undef _DAI_INTEL_CL_VERSION
#endif
#if defined(__INTEL_COMPILER) && defined(__INTEL_COMPILER_UPDATE) && defined(__ICL)
#  define _DAI_INTEL_CL_VERSION _DAI_HEDLEY_VERSION_ENCODE(__INTEL_COMPILER, __INTEL_COMPILER_UPDATE, 0)
#endif

#if defined(_DAI_INTEL_CL_VERSION_CHECK)
#  undef _DAI_INTEL_CL_VERSION_CHECK
#endif
#if defined(_DAI_INTEL_CL_VERSION)
#  define _DAI_INTEL_CL_VERSION_CHECK(major,minor,patch) (_DAI_INTEL_CL_VERSION >= _DAI_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
#  define _DAI_INTEL_CL_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(_DAI_PGI_VERSION)
#  undef _DAI_PGI_VERSION
#endif
#if defined(__PGI) && defined(__PGIC__) && defined(__PGIC_MINOR__) && defined(__PGIC_PATCHLEVEL__)
#  define _DAI_PGI_VERSION _DAI_HEDLEY_VERSION_ENCODE(__PGIC__, __PGIC_MINOR__, __PGIC_PATCHLEVEL__)
#endif

#if defined(_DAI_PGI_VERSION_CHECK)
#  undef _DAI_PGI_VERSION_CHECK
#endif
#if defined(_DAI_PGI_VERSION)
#  define _DAI_PGI_VERSION_CHECK(major,minor,patch) (_DAI_PGI_VERSION >= _DAI_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
#  define _DAI_PGI_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(_DAI_SUNPRO_VERSION)
#  undef _DAI_SUNPRO_VERSION
#endif
#if defined(__SUNPRO_C) && (__SUNPRO_C > 0x1000)
#  define _DAI_SUNPRO_VERSION _DAI_HEDLEY_VERSION_ENCODE((((__SUNPRO_C >> 16) & 0xf) * 10) + ((__SUNPRO_C >> 12) & 0xf), (((__SUNPRO_C >> 8) & 0xf) * 10) + ((__SUNPRO_C >> 4) & 0xf), (__SUNPRO_C & 0xf) * 10)
#elif defined(__SUNPRO_C)
#  define _DAI_SUNPRO_VERSION _DAI_HEDLEY_VERSION_ENCODE((__SUNPRO_C >> 8) & 0xf, (__SUNPRO_C >> 4) & 0xf, (__SUNPRO_C) & 0xf)
#elif defined(__SUNPRO_CC) && (__SUNPRO_CC > 0x1000)
#  define _DAI_SUNPRO_VERSION _DAI_HEDLEY_VERSION_ENCODE((((__SUNPRO_CC >> 16) & 0xf) * 10) + ((__SUNPRO_CC >> 12) & 0xf), (((__SUNPRO_CC >> 8) & 0xf) * 10) + ((__SUNPRO_CC >> 4) & 0xf), (__SUNPRO_CC & 0xf) * 10)
#elif defined(__SUNPRO_CC)
#  define _DAI_SUNPRO_VERSION _DAI_HEDLEY_VERSION_ENCODE((__SUNPRO_CC >> 8) & 0xf, (__SUNPRO_CC >> 4) & 0xf, (__SUNPRO_CC) & 0xf)
#endif

#if defined(_DAI_SUNPRO_VERSION_CHECK)
#  undef _DAI_SUNPRO_VERSION_CHECK
#endif
#if defined(_DAI_SUNPRO_VERSION)
#  define _DAI_SUNPRO_VERSION_CHECK(major,minor,patch) (_DAI_SUNPRO_VERSION >= _DAI_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
#  define _DAI_SUNPRO_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(_DAI_EMSCRIPTEN_VERSION)
#  undef _DAI_EMSCRIPTEN_VERSION
#endif
#if defined(__EMSCRIPTEN__)
#  define _DAI_EMSCRIPTEN_VERSION _DAI_HEDLEY_VERSION_ENCODE(__EMSCRIPTEN_major__, __EMSCRIPTEN_minor__, __EMSCRIPTEN_tiny__)
#endif

#if defined(_DAI_EMSCRIPTEN_VERSION_CHECK)
#  undef _DAI_EMSCRIPTEN_VERSION_CHECK
#endif
#if defined(_DAI_EMSCRIPTEN_VERSION)
#  define _DAI_EMSCRIPTEN_VERSION_CHECK(major,minor,patch) (_DAI_EMSCRIPTEN_VERSION >= _DAI_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
#  define _DAI_EMSCRIPTEN_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(_DAI_ARM_VERSION)
#  undef _DAI_ARM_VERSION
#endif
#if defined(__CC_ARM) && defined(__ARMCOMPILER_VERSION)
#  define _DAI_ARM_VERSION _DAI_HEDLEY_VERSION_ENCODE(__ARMCOMPILER_VERSION / 1000000, (__ARMCOMPILER_VERSION % 1000000) / 10000, (__ARMCOMPILER_VERSION % 10000) / 100)
#elif defined(__CC_ARM) && defined(__ARMCC_VERSION)
#  define _DAI_ARM_VERSION _DAI_HEDLEY_VERSION_ENCODE(__ARMCC_VERSION / 1000000, (__ARMCC_VERSION % 1000000) / 10000, (__ARMCC_VERSION % 10000) / 100)
#endif

#if defined(_DAI_ARM_VERSION_CHECK)
#  undef _DAI_ARM_VERSION_CHECK
#endif
#if defined(_DAI_ARM_VERSION)
#  define _DAI_ARM_VERSION_CHECK(major,minor,patch) (_DAI_ARM_VERSION >= _DAI_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
#  define _DAI_ARM_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(_DAI_IBM_VERSION)
#  undef _DAI_IBM_VERSION
#endif
#if defined(__ibmxl__)
#  define _DAI_IBM_VERSION _DAI_HEDLEY_VERSION_ENCODE(__ibmxl_version__, __ibmxl_release__, __ibmxl_modification__)
#elif defined(__xlC__) && defined(__xlC_ver__)
#  define _DAI_IBM_VERSION _DAI_HEDLEY_VERSION_ENCODE(__xlC__ >> 8, __xlC__ & 0xff, (__xlC_ver__ >> 8) & 0xff)
#elif defined(__xlC__)
#  define _DAI_IBM_VERSION _DAI_HEDLEY_VERSION_ENCODE(__xlC__ >> 8, __xlC__ & 0xff, 0)
#endif

#if defined(_DAI_IBM_VERSION_CHECK)
#  undef _DAI_IBM_VERSION_CHECK
#endif
#if defined(_DAI_IBM_VERSION)
#  define _DAI_IBM_VERSION_CHECK(major,minor,patch) (_DAI_IBM_VERSION >= _DAI_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
#  define _DAI_IBM_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(_DAI_TI_VERSION)
#  undef _DAI_TI_VERSION
#endif
#if \
    defined(__TI_COMPILER_VERSION__) && \
    ( \
      defined(__TMS470__) || defined(__TI_ARM__) || \
      defined(__MSP430__) || \
      defined(__TMS320C2000__) \
    )
#  if (__TI_COMPILER_VERSION__ >= 16000000)
#    define _DAI_TI_VERSION _DAI_HEDLEY_VERSION_ENCODE(__TI_COMPILER_VERSION__ / 1000000, (__TI_COMPILER_VERSION__ % 1000000) / 1000, (__TI_COMPILER_VERSION__ % 1000))
#  endif
#endif

#if defined(_DAI_TI_VERSION_CHECK)
#  undef _DAI_TI_VERSION_CHECK
#endif
#if defined(_DAI_TI_VERSION)
#  define _DAI_TI_VERSION_CHECK(major,minor,patch) (_DAI_TI_VERSION >= _DAI_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
#  define _DAI_TI_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(_DAI_TI_CL2000_VERSION)
#  undef _DAI_TI_CL2000_VERSION
#endif
#if defined(__TI_COMPILER_VERSION__) && defined(__TMS320C2000__)
#  define _DAI_TI_CL2000_VERSION _DAI_HEDLEY_VERSION_ENCODE(__TI_COMPILER_VERSION__ / 1000000, (__TI_COMPILER_VERSION__ % 1000000) / 1000, (__TI_COMPILER_VERSION__ % 1000))
#endif

#if defined(_DAI_TI_CL2000_VERSION_CHECK)
#  undef _DAI_TI_CL2000_VERSION_CHECK
#endif
#if defined(_DAI_TI_CL2000_VERSION)
#  define _DAI_TI_CL2000_VERSION_CHECK(major,minor,patch) (_DAI_TI_CL2000_VERSION >= _DAI_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
#  define _DAI_TI_CL2000_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(_DAI_TI_CL430_VERSION)
#  undef _DAI_TI_CL430_VERSION
#endif
#if defined(__TI_COMPILER_VERSION__) && defined(__MSP430__)
#  define _DAI_TI_CL430_VERSION _DAI_HEDLEY_VERSION_ENCODE(__TI_COMPILER_VERSION__ / 1000000, (__TI_COMPILER_VERSION__ % 1000000) / 1000, (__TI_COMPILER_VERSION__ % 1000))
#endif

#if defined(_DAI_TI_CL430_VERSION_CHECK)
#  undef _DAI_TI_CL430_VERSION_CHECK
#endif
#if defined(_DAI_TI_CL430_VERSION)
#  define _DAI_TI_CL430_VERSION_CHECK(major,minor,patch) (_DAI_TI_CL430_VERSION >= _DAI_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
#  define _DAI_TI_CL430_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(_DAI_TI_ARMCL_VERSION)
#  undef _DAI_TI_ARMCL_VERSION
#endif
#if defined(__TI_COMPILER_VERSION__) && (defined(__TMS470__) || defined(__TI_ARM__))
#  define _DAI_TI_ARMCL_VERSION _DAI_HEDLEY_VERSION_ENCODE(__TI_COMPILER_VERSION__ / 1000000, (__TI_COMPILER_VERSION__ % 1000000) / 1000, (__TI_COMPILER_VERSION__ % 1000))
#endif

#if defined(_DAI_TI_ARMCL_VERSION_CHECK)
#  undef _DAI_TI_ARMCL_VERSION_CHECK
#endif
#if defined(_DAI_TI_ARMCL_VERSION)
#  define _DAI_TI_ARMCL_VERSION_CHECK(major,minor,patch) (_DAI_TI_ARMCL_VERSION >= _DAI_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
#  define _DAI_TI_ARMCL_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(_DAI_TI_CL6X_VERSION)
#  undef _DAI_TI_CL6X_VERSION
#endif
#if defined(__TI_COMPILER_VERSION__) && defined(__TMS320C6X__)
#  define _DAI_TI_CL6X_VERSION _DAI_HEDLEY_VERSION_ENCODE(__TI_COMPILER_VERSION__ / 1000000, (__TI_COMPILER_VERSION__ % 1000000) / 1000, (__TI_COMPILER_VERSION__ % 1000))
#endif

#if defined(_DAI_TI_CL6X_VERSION_CHECK)
#  undef _DAI_TI_CL6X_VERSION_CHECK
#endif
#if defined(_DAI_TI_CL6X_VERSION)
#  define _DAI_TI_CL6X_VERSION_CHECK(major,minor,patch) (_DAI_TI_CL6X_VERSION >= _DAI_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
#  define _DAI_TI_CL6X_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(_DAI_TI_CL7X_VERSION)
#  undef _DAI_TI_CL7X_VERSION
#endif
#if defined(__TI_COMPILER_VERSION__) && defined(__C7000__)
#  define _DAI_TI_CL7X_VERSION _DAI_HEDLEY_VERSION_ENCODE(__TI_COMPILER_VERSION__ / 1000000, (__TI_COMPILER_VERSION__ % 1000000) / 1000, (__TI_COMPILER_VERSION__ % 1000))
#endif

#if defined(_DAI_TI_CL7X_VERSION_CHECK)
#  undef _DAI_TI_CL7X_VERSION_CHECK
#endif
#if defined(_DAI_TI_CL7X_VERSION)
#  define _DAI_TI_CL7X_VERSION_CHECK(major,minor,patch) (_DAI_TI_CL7X_VERSION >= _DAI_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
#  define _DAI_TI_CL7X_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(_DAI_TI_CLPRU_VERSION)
#  undef _DAI_TI_CLPRU_VERSION
#endif
#if defined(__TI_COMPILER_VERSION__) && defined(__PRU__)
#  define _DAI_TI_CLPRU_VERSION _DAI_HEDLEY_VERSION_ENCODE(__TI_COMPILER_VERSION__ / 1000000, (__TI_COMPILER_VERSION__ % 1000000) / 1000, (__TI_COMPILER_VERSION__ % 1000))
#endif

#if defined(_DAI_TI_CLPRU_VERSION_CHECK)
#  undef _DAI_TI_CLPRU_VERSION_CHECK
#endif
#if defined(_DAI_TI_CLPRU_VERSION)
#  define _DAI_TI_CLPRU_VERSION_CHECK(major,minor,patch) (_DAI_TI_CLPRU_VERSION >= _DAI_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
#  define _DAI_TI_CLPRU_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(_DAI_CRAY_VERSION)
#  undef _DAI_CRAY_VERSION
#endif
#if defined(_CRAYC)
#  if defined(_RELEASE_PATCHLEVEL)
#    define _DAI_CRAY_VERSION _DAI_HEDLEY_VERSION_ENCODE(_RELEASE_MAJOR, _RELEASE_MINOR, _RELEASE_PATCHLEVEL)
#  else
#    define _DAI_CRAY_VERSION _DAI_HEDLEY_VERSION_ENCODE(_RELEASE_MAJOR, _RELEASE_MINOR, 0)
#  endif
#endif

#if defined(_DAI_CRAY_VERSION_CHECK)
#  undef _DAI_CRAY_VERSION_CHECK
#endif
#if defined(_DAI_CRAY_VERSION)
#  define _DAI_CRAY_VERSION_CHECK(major,minor,patch) (_DAI_CRAY_VERSION >= _DAI_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
#  define _DAI_CRAY_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(_DAI_IAR_VERSION)
#  undef _DAI_IAR_VERSION
#endif
#if defined(__IAR_SYSTEMS_ICC__)
#  if __VER__ > 1000
#    define _DAI_IAR_VERSION _DAI_HEDLEY_VERSION_ENCODE((__VER__ / 1000000), ((__VER__ / 1000) % 1000), (__VER__ % 1000))
#  else
#    define _DAI_IAR_VERSION _DAI_HEDLEY_VERSION_ENCODE(__VER__ / 100, __VER__ % 100, 0)
#  endif
#endif

#if defined(_DAI_IAR_VERSION_CHECK)
#  undef _DAI_IAR_VERSION_CHECK
#endif
#if defined(_DAI_IAR_VERSION)
#  define _DAI_IAR_VERSION_CHECK(major,minor,patch) (_DAI_IAR_VERSION >= _DAI_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
#  define _DAI_IAR_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(_DAI_TINYC_VERSION)
#  undef _DAI_TINYC_VERSION
#endif
#if defined(__TINYC__)
#  define _DAI_TINYC_VERSION _DAI_HEDLEY_VERSION_ENCODE(__TINYC__ / 1000, (__TINYC__ / 100) % 10, __TINYC__ % 100)
#endif

#if defined(_DAI_TINYC_VERSION_CHECK)
#  undef _DAI_TINYC_VERSION_CHECK
#endif
#if defined(_DAI_TINYC_VERSION)
#  define _DAI_TINYC_VERSION_CHECK(major,minor,patch) (_DAI_TINYC_VERSION >= _DAI_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
#  define _DAI_TINYC_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(_DAI_DMC_VERSION)
#  undef _DAI_DMC_VERSION
#endif
#if defined(__DMC__)
#  define _DAI_DMC_VERSION _DAI_HEDLEY_VERSION_ENCODE(__DMC__ >> 8, (__DMC__ >> 4) & 0xf, __DMC__ & 0xf)
#endif

#if defined(_DAI_DMC_VERSION_CHECK)
#  undef _DAI_DMC_VERSION_CHECK
#endif
#if defined(_DAI_DMC_VERSION)
#  define _DAI_DMC_VERSION_CHECK(major,minor,patch) (_DAI_DMC_VERSION >= _DAI_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
#  define _DAI_DMC_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(_DAI_COMPCERT_VERSION)
#  undef _DAI_COMPCERT_VERSION
#endif
#if defined(__COMPCERT_VERSION__)
#  define _DAI_COMPCERT_VERSION _DAI_HEDLEY_VERSION_ENCODE(__COMPCERT_VERSION__ / 10000, (__COMPCERT_VERSION__ / 100) % 100, __COMPCERT_VERSION__ % 100)
#endif

#if defined(_DAI_COMPCERT_VERSION_CHECK)
#  undef _DAI_COMPCERT_VERSION_CHECK
#endif
#if defined(_DAI_COMPCERT_VERSION)
#  define _DAI_COMPCERT_VERSION_CHECK(major,minor,patch) (_DAI_COMPCERT_VERSION >= _DAI_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
#  define _DAI_COMPCERT_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(_DAI_PELLES_VERSION)
#  undef _DAI_PELLES_VERSION
#endif
#if defined(__POCC__)
#  define _DAI_PELLES_VERSION _DAI_HEDLEY_VERSION_ENCODE(__POCC__ / 100, __POCC__ % 100, 0)
#endif

#if defined(_DAI_PELLES_VERSION_CHECK)
#  undef _DAI_PELLES_VERSION_CHECK
#endif
#if defined(_DAI_PELLES_VERSION)
#  define _DAI_PELLES_VERSION_CHECK(major,minor,patch) (_DAI_PELLES_VERSION >= _DAI_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
#  define _DAI_PELLES_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(_DAI_MCST_LCC_VERSION)
#  undef _DAI_MCST_LCC_VERSION
#endif
#if defined(__LCC__) && defined(__LCC_MINOR__)
#  define _DAI_MCST_LCC_VERSION _DAI_HEDLEY_VERSION_ENCODE(__LCC__ / 100, __LCC__ % 100, __LCC_MINOR__)
#endif

#if defined(_DAI_MCST_LCC_VERSION_CHECK)
#  undef _DAI_MCST_LCC_VERSION_CHECK
#endif
#if defined(_DAI_MCST_LCC_VERSION)
#  define _DAI_MCST_LCC_VERSION_CHECK(major,minor,patch) (_DAI_MCST_LCC_VERSION >= _DAI_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
#  define _DAI_MCST_LCC_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(_DAI_GCC_VERSION)
#  undef _DAI_GCC_VERSION
#endif
#if \
  defined(_DAI_GNUC_VERSION) && \
  !defined(__clang__) && \
  !defined(_DAI_INTEL_VERSION) && \
  !defined(_DAI_PGI_VERSION) && \
  !defined(_DAI_ARM_VERSION) && \
  !defined(_DAI_CRAY_VERSION) && \
  !defined(_DAI_TI_VERSION) && \
  !defined(_DAI_TI_ARMCL_VERSION) && \
  !defined(_DAI_TI_CL430_VERSION) && \
  !defined(_DAI_TI_CL2000_VERSION) && \
  !defined(_DAI_TI_CL6X_VERSION) && \
  !defined(_DAI_TI_CL7X_VERSION) && \
  !defined(_DAI_TI_CLPRU_VERSION) && \
  !defined(__COMPCERT__) && \
  !defined(_DAI_MCST_LCC_VERSION)
#  define _DAI_GCC_VERSION _DAI_GNUC_VERSION
#endif

#if defined(_DAI_GCC_VERSION_CHECK)
#  undef _DAI_GCC_VERSION_CHECK
#endif
#if defined(_DAI_GCC_VERSION)
#  define _DAI_GCC_VERSION_CHECK(major,minor,patch) (_DAI_GCC_VERSION >= _DAI_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
#  define _DAI_GCC_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(_DAI_HAS_ATTRIBUTE)
#  undef _DAI_HAS_ATTRIBUTE
#endif
#if \
  defined(__has_attribute) && \
  ( \
    (!defined(_DAI_IAR_VERSION) || _DAI_IAR_VERSION_CHECK(8,5,9)) \
  )
#  define _DAI_HAS_ATTRIBUTE(attribute) __has_attribute(attribute)
#else
#  define _DAI_HAS_ATTRIBUTE(attribute) (0)
#endif

#if defined(_DAI_GNUC_HAS_ATTRIBUTE)
#  undef _DAI_GNUC_HAS_ATTRIBUTE
#endif
#if defined(__has_attribute)
#  define _DAI_GNUC_HAS_ATTRIBUTE(attribute,major,minor,patch) _DAI_HAS_ATTRIBUTE(attribute)
#else
#  define _DAI_GNUC_HAS_ATTRIBUTE(attribute,major,minor,patch) _DAI_GNUC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(_DAI_GCC_HAS_ATTRIBUTE)
#  undef _DAI_GCC_HAS_ATTRIBUTE
#endif
#if defined(__has_attribute)
#  define _DAI_GCC_HAS_ATTRIBUTE(attribute,major,minor,patch) _DAI_HAS_ATTRIBUTE(attribute)
#else
#  define _DAI_GCC_HAS_ATTRIBUTE(attribute,major,minor,patch) _DAI_GCC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(_DAI_HAS_CPP_ATTRIBUTE)
#  undef _DAI_HAS_CPP_ATTRIBUTE
#endif
#if \
  defined(__has_cpp_attribute) && \
  defined(__cplusplus) && \
  (!defined(_DAI_SUNPRO_VERSION) || _DAI_SUNPRO_VERSION_CHECK(5,15,0))
#  define _DAI_HAS_CPP_ATTRIBUTE(attribute) __has_cpp_attribute(attribute)
#else
#  define _DAI_HAS_CPP_ATTRIBUTE(attribute) (0)
#endif

#if defined(_DAI_HAS_CPP_ATTRIBUTE_NS)
#  undef _DAI_HAS_CPP_ATTRIBUTE_NS
#endif
#if !defined(__cplusplus) || !defined(__has_cpp_attribute)
#  define _DAI_HAS_CPP_ATTRIBUTE_NS(ns,attribute) (0)
#elif \
  !defined(_DAI_PGI_VERSION) && \
  !defined(_DAI_IAR_VERSION) && \
  (!defined(_DAI_SUNPRO_VERSION) || _DAI_SUNPRO_VERSION_CHECK(5,15,0)) && \
  (!defined(_DAI_MSVC_VERSION) || _DAI_MSVC_VERSION_CHECK(19,20,0))
#  define _DAI_HAS_CPP_ATTRIBUTE_NS(ns,attribute) _DAI_HAS_CPP_ATTRIBUTE(ns::attribute)
#else
#  define _DAI_HAS_CPP_ATTRIBUTE_NS(ns,attribute) (0)
#endif

#if defined(_DAI_GNUC_HAS_CPP_ATTRIBUTE)
#  undef _DAI_GNUC_HAS_CPP_ATTRIBUTE
#endif
#if defined(__has_cpp_attribute) && defined(__cplusplus)
#  define _DAI_GNUC_HAS_CPP_ATTRIBUTE(attribute,major,minor,patch) __has_cpp_attribute(attribute)
#else
#  define _DAI_GNUC_HAS_CPP_ATTRIBUTE(attribute,major,minor,patch) _DAI_GNUC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(_DAI_GCC_HAS_CPP_ATTRIBUTE)
#  undef _DAI_GCC_HAS_CPP_ATTRIBUTE
#endif
#if defined(__has_cpp_attribute) && defined(__cplusplus)
#  define _DAI_GCC_HAS_CPP_ATTRIBUTE(attribute,major,minor,patch) __has_cpp_attribute(attribute)
#else
#  define _DAI_GCC_HAS_CPP_ATTRIBUTE(attribute,major,minor,patch) _DAI_GCC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(_DAI_HAS_BUILTIN)
#  undef _DAI_HAS_BUILTIN
#endif
#if defined(__has_builtin)
#  define _DAI_HAS_BUILTIN(builtin) __has_builtin(builtin)
#else
#  define _DAI_HAS_BUILTIN(builtin) (0)
#endif

#if defined(_DAI_GNUC_HAS_BUILTIN)
#  undef _DAI_GNUC_HAS_BUILTIN
#endif
#if defined(__has_builtin)
#  define _DAI_GNUC_HAS_BUILTIN(builtin,major,minor,patch) __has_builtin(builtin)
#else
#  define _DAI_GNUC_HAS_BUILTIN(builtin,major,minor,patch) _DAI_GNUC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(_DAI_GCC_HAS_BUILTIN)
#  undef _DAI_GCC_HAS_BUILTIN
#endif
#if defined(__has_builtin)
#  define _DAI_GCC_HAS_BUILTIN(builtin,major,minor,patch) __has_builtin(builtin)
#else
#  define _DAI_GCC_HAS_BUILTIN(builtin,major,minor,patch) _DAI_GCC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(_DAI_HAS_FEATURE)
#  undef _DAI_HAS_FEATURE
#endif
#if defined(__has_feature)
#  define _DAI_HAS_FEATURE(feature) __has_feature(feature)
#else
#  define _DAI_HAS_FEATURE(feature) (0)
#endif

#if defined(_DAI_GNUC_HAS_FEATURE)
#  undef _DAI_GNUC_HAS_FEATURE
#endif
#if defined(__has_feature)
#  define _DAI_GNUC_HAS_FEATURE(feature,major,minor,patch) __has_feature(feature)
#else
#  define _DAI_GNUC_HAS_FEATURE(feature,major,minor,patch) _DAI_GNUC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(_DAI_GCC_HAS_FEATURE)
#  undef _DAI_GCC_HAS_FEATURE
#endif
#if defined(__has_feature)
#  define _DAI_GCC_HAS_FEATURE(feature,major,minor,patch) __has_feature(feature)
#else
#  define _DAI_GCC_HAS_FEATURE(feature,major,minor,patch) _DAI_GCC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(_DAI_HAS_EXTENSION)
#  undef _DAI_HAS_EXTENSION
#endif
#if defined(__has_extension)
#  define _DAI_HAS_EXTENSION(extension) __has_extension(extension)
#else
#  define _DAI_HAS_EXTENSION(extension) (0)
#endif

#if defined(_DAI_GNUC_HAS_EXTENSION)
#  undef _DAI_GNUC_HAS_EXTENSION
#endif
#if defined(__has_extension)
#  define _DAI_GNUC_HAS_EXTENSION(extension,major,minor,patch) __has_extension(extension)
#else
#  define _DAI_GNUC_HAS_EXTENSION(extension,major,minor,patch) _DAI_GNUC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(_DAI_GCC_HAS_EXTENSION)
#  undef _DAI_GCC_HAS_EXTENSION
#endif
#if defined(__has_extension)
#  define _DAI_GCC_HAS_EXTENSION(extension,major,minor,patch) __has_extension(extension)
#else
#  define _DAI_GCC_HAS_EXTENSION(extension,major,minor,patch) _DAI_GCC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(_DAI_HAS_DECLSPEC_ATTRIBUTE)
#  undef _DAI_HAS_DECLSPEC_ATTRIBUTE
#endif
#if defined(__has_declspec_attribute)
#  define _DAI_HAS_DECLSPEC_ATTRIBUTE(attribute) __has_declspec_attribute(attribute)
#else
#  define _DAI_HAS_DECLSPEC_ATTRIBUTE(attribute) (0)
#endif

#if defined(_DAI_GNUC_HAS_DECLSPEC_ATTRIBUTE)
#  undef _DAI_GNUC_HAS_DECLSPEC_ATTRIBUTE
#endif
#if defined(__has_declspec_attribute)
#  define _DAI_GNUC_HAS_DECLSPEC_ATTRIBUTE(attribute,major,minor,patch) __has_declspec_attribute(attribute)
#else
#  define _DAI_GNUC_HAS_DECLSPEC_ATTRIBUTE(attribute,major,minor,patch) _DAI_GNUC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(_DAI_GCC_HAS_DECLSPEC_ATTRIBUTE)
#  undef _DAI_GCC_HAS_DECLSPEC_ATTRIBUTE
#endif
#if defined(__has_declspec_attribute)
#  define _DAI_GCC_HAS_DECLSPEC_ATTRIBUTE(attribute,major,minor,patch) __has_declspec_attribute(attribute)
#else
#  define _DAI_GCC_HAS_DECLSPEC_ATTRIBUTE(attribute,major,minor,patch) _DAI_GCC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(_DAI_HAS_WARNING)
#  undef _DAI_HAS_WARNING
#endif
#if defined(__has_warning)
#  define _DAI_HAS_WARNING(warning) __has_warning(warning)
#else
#  define _DAI_HAS_WARNING(warning) (0)
#endif

#if defined(_DAI_GNUC_HAS_WARNING)
#  undef _DAI_GNUC_HAS_WARNING
#endif
#if defined(__has_warning)
#  define _DAI_GNUC_HAS_WARNING(warning,major,minor,patch) __has_warning(warning)
#else
#  define _DAI_GNUC_HAS_WARNING(warning,major,minor,patch) _DAI_GNUC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(_DAI_GCC_HAS_WARNING)
#  undef _DAI_GCC_HAS_WARNING
#endif
#if defined(__has_warning)
#  define _DAI_GCC_HAS_WARNING(warning,major,minor,patch) __has_warning(warning)
#else
#  define _DAI_GCC_HAS_WARNING(warning,major,minor,patch) _DAI_GCC_VERSION_CHECK(major,minor,patch)
#endif

#if \
  (defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)) || \
  defined(__clang__) || \
  _DAI_GCC_VERSION_CHECK(3,0,0) || \
  _DAI_INTEL_VERSION_CHECK(13,0,0) || \
  _DAI_IAR_VERSION_CHECK(8,0,0) || \
  _DAI_PGI_VERSION_CHECK(18,4,0) || \
  _DAI_ARM_VERSION_CHECK(4,1,0) || \
  _DAI_TI_VERSION_CHECK(15,12,0) || \
  _DAI_TI_ARMCL_VERSION_CHECK(4,7,0) || \
  _DAI_TI_CL430_VERSION_CHECK(2,0,1) || \
  _DAI_TI_CL2000_VERSION_CHECK(6,1,0) || \
  _DAI_TI_CL6X_VERSION_CHECK(7,0,0) || \
  _DAI_TI_CL7X_VERSION_CHECK(1,2,0) || \
  _DAI_TI_CLPRU_VERSION_CHECK(2,1,0) || \
  _DAI_CRAY_VERSION_CHECK(5,0,0) || \
  _DAI_TINYC_VERSION_CHECK(0,9,17) || \
  _DAI_SUNPRO_VERSION_CHECK(8,0,0) || \
  (_DAI_IBM_VERSION_CHECK(10,1,0) && defined(__C99_PRAGMA_OPERATOR))
#  define _DAI_PRAGMA(value) _Pragma(#value)
#elif _DAI_MSVC_VERSION_CHECK(15,0,0)
#  define _DAI_PRAGMA(value) __pragma(value)
#else
#  define _DAI_PRAGMA(value)
#endif

#if defined(_DAI_DIAGNOSTIC_PUSH)
#  undef _DAI_DIAGNOSTIC_PUSH
#endif
#if defined(_DAI_DIAGNOSTIC_POP)
#  undef _DAI_DIAGNOSTIC_POP
#endif
#if defined(__clang__)
#  define _DAI_DIAGNOSTIC_PUSH _Pragma("clang diagnostic push")
#  define _DAI_DIAGNOSTIC_POP _Pragma("clang diagnostic pop")
#elif _DAI_INTEL_VERSION_CHECK(13,0,0)
#  define _DAI_DIAGNOSTIC_PUSH _Pragma("warning(push)")
#  define _DAI_DIAGNOSTIC_POP _Pragma("warning(pop)")
#elif _DAI_GCC_VERSION_CHECK(4,6,0)
#  define _DAI_DIAGNOSTIC_PUSH _Pragma("GCC diagnostic push")
#  define _DAI_DIAGNOSTIC_POP _Pragma("GCC diagnostic pop")
#elif \
  _DAI_MSVC_VERSION_CHECK(15,0,0) || \
  _DAI_INTEL_CL_VERSION_CHECK(2021,1,0)
#  define _DAI_DIAGNOSTIC_PUSH __pragma(warning(push))
#  define _DAI_DIAGNOSTIC_POP __pragma(warning(pop))
#elif _DAI_ARM_VERSION_CHECK(5,6,0)
#  define _DAI_DIAGNOSTIC_PUSH _Pragma("push")
#  define _DAI_DIAGNOSTIC_POP _Pragma("pop")
#elif \
    _DAI_TI_VERSION_CHECK(15,12,0) || \
    _DAI_TI_ARMCL_VERSION_CHECK(5,2,0) || \
    _DAI_TI_CL430_VERSION_CHECK(4,4,0) || \
    _DAI_TI_CL6X_VERSION_CHECK(8,1,0) || \
    _DAI_TI_CL7X_VERSION_CHECK(1,2,0) || \
    _DAI_TI_CLPRU_VERSION_CHECK(2,1,0)
#  define _DAI_DIAGNOSTIC_PUSH _Pragma("diag_push")
#  define _DAI_DIAGNOSTIC_POP _Pragma("diag_pop")
#elif _DAI_PELLES_VERSION_CHECK(2,90,0)
#  define _DAI_DIAGNOSTIC_PUSH _Pragma("warning(push)")
#  define _DAI_DIAGNOSTIC_POP _Pragma("warning(pop)")
#else
#  define _DAI_DIAGNOSTIC_PUSH
#  define _DAI_DIAGNOSTIC_POP
#endif

/* _DAI_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_ is for
   HEDLEY INTERNAL USE ONLY.  API subject to change without notice. */
#if defined(_DAI_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_)
#  undef _DAI_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_
#endif
#if defined(__cplusplus)
#  if _DAI_HAS_WARNING("-Wc++98-compat")
#    if _DAI_HAS_WARNING("-Wc++17-extensions")
#      if _DAI_HAS_WARNING("-Wc++1z-extensions")
#        define _DAI_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_(xpr) \
           _DAI_DIAGNOSTIC_PUSH \
           _Pragma("clang diagnostic ignored \"-Wc++98-compat\"") \
           _Pragma("clang diagnostic ignored \"-Wc++17-extensions\"") \
           _Pragma("clang diagnostic ignored \"-Wc++1z-extensions\"") \
           xpr \
           _DAI_DIAGNOSTIC_POP
#      else
#        define _DAI_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_(xpr) \
           _DAI_DIAGNOSTIC_PUSH \
           _Pragma("clang diagnostic ignored \"-Wc++98-compat\"") \
           _Pragma("clang diagnostic ignored \"-Wc++17-extensions\"") \
           xpr \
           _DAI_DIAGNOSTIC_POP
#      endif
#    else
#      define _DAI_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_(xpr) \
         _DAI_DIAGNOSTIC_PUSH \
         _Pragma("clang diagnostic ignored \"-Wc++98-compat\"") \
         xpr \
         _DAI_DIAGNOSTIC_POP
#    endif
#  endif
#endif
#if !defined(_DAI_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_)
#  define _DAI_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_(x) x
#endif

#if defined(_DAI_CONST_CAST)
#  undef _DAI_CONST_CAST
#endif
#if defined(__cplusplus)
#  define _DAI_CONST_CAST(T, expr) (const_cast<T>(expr))
#elif \
  _DAI_HAS_WARNING("-Wcast-qual") || \
  _DAI_GCC_VERSION_CHECK(4,6,0) || \
  _DAI_INTEL_VERSION_CHECK(13,0,0)
#  define _DAI_CONST_CAST(T, expr) (__extension__ ({ \
      _DAI_DIAGNOSTIC_PUSH \
      _DAI_DIAGNOSTIC_DISABLE_CAST_QUAL \
      ((T) (expr)); \
      _DAI_DIAGNOSTIC_POP \
    }))
#else
#  define _DAI_CONST_CAST(T, expr) ((T) (expr))
#endif

#if defined(_DAI_REINTERPRET_CAST)
#  undef _DAI_REINTERPRET_CAST
#endif
#if defined(__cplusplus)
#  define _DAI_REINTERPRET_CAST(T, expr) (reinterpret_cast<T>(expr))
#else
#  define _DAI_REINTERPRET_CAST(T, expr) ((T) (expr))
#endif

#if defined(_DAI_STATIC_CAST)
#  undef _DAI_STATIC_CAST
#endif
#if defined(__cplusplus)
#  define _DAI_STATIC_CAST(T, expr) (static_cast<T>(expr))
#else
#  define _DAI_STATIC_CAST(T, expr) ((T) (expr))
#endif

#if defined(_DAI_CPP_CAST)
#  undef _DAI_CPP_CAST
#endif
#if defined(__cplusplus)
#  if _DAI_HAS_WARNING("-Wold-style-cast")
#    define _DAI_CPP_CAST(T, expr) \
       _DAI_DIAGNOSTIC_PUSH \
       _Pragma("clang diagnostic ignored \"-Wold-style-cast\"") \
       ((T) (expr)) \
       _DAI_DIAGNOSTIC_POP
#  elif _DAI_IAR_VERSION_CHECK(8,3,0)
#    define _DAI_CPP_CAST(T, expr) \
       _DAI_DIAGNOSTIC_PUSH \
       _Pragma("diag_suppress=Pe137") \
       _DAI_DIAGNOSTIC_POP
#  else
#    define _DAI_CPP_CAST(T, expr) ((T) (expr))
#  endif
#else
#  define _DAI_CPP_CAST(T, expr) (expr)
#endif

#if defined(_DAI_DIAGNOSTIC_DISABLE_DEPRECATED)
#  undef _DAI_DIAGNOSTIC_DISABLE_DEPRECATED
#endif
#if _DAI_HAS_WARNING("-Wdeprecated-declarations")
#  define _DAI_DIAGNOSTIC_DISABLE_DEPRECATED _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"")
#elif _DAI_INTEL_VERSION_CHECK(13,0,0)
#  define _DAI_DIAGNOSTIC_DISABLE_DEPRECATED _Pragma("warning(disable:1478 1786)")
#elif _DAI_INTEL_CL_VERSION_CHECK(2021,1,0)
#  define _DAI_DIAGNOSTIC_DISABLE_DEPRECATED __pragma(warning(disable:1478 1786))
#elif _DAI_PGI_VERSION_CHECK(20,7,0)
#  define _DAI_DIAGNOSTIC_DISABLE_DEPRECATED _Pragma("diag_suppress 1215,1216,1444,1445")
#elif _DAI_PGI_VERSION_CHECK(17,10,0)
#  define _DAI_DIAGNOSTIC_DISABLE_DEPRECATED _Pragma("diag_suppress 1215,1444")
#elif _DAI_GCC_VERSION_CHECK(4,3,0)
#  define _DAI_DIAGNOSTIC_DISABLE_DEPRECATED _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")
#elif _DAI_MSVC_VERSION_CHECK(15,0,0)
#  define _DAI_DIAGNOSTIC_DISABLE_DEPRECATED __pragma(warning(disable:4996))
#elif _DAI_MCST_LCC_VERSION_CHECK(1,25,10)
#  define _DAI_DIAGNOSTIC_DISABLE_DEPRECATED _Pragma("diag_suppress 1215,1444")
#elif \
    _DAI_TI_VERSION_CHECK(15,12,0) || \
    (_DAI_TI_ARMCL_VERSION_CHECK(4,8,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    _DAI_TI_ARMCL_VERSION_CHECK(5,2,0) || \
    (_DAI_TI_CL2000_VERSION_CHECK(6,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    _DAI_TI_CL2000_VERSION_CHECK(6,4,0) || \
    (_DAI_TI_CL430_VERSION_CHECK(4,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    _DAI_TI_CL430_VERSION_CHECK(4,3,0) || \
    (_DAI_TI_CL6X_VERSION_CHECK(7,2,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    _DAI_TI_CL6X_VERSION_CHECK(7,5,0) || \
    _DAI_TI_CL7X_VERSION_CHECK(1,2,0) || \
    _DAI_TI_CLPRU_VERSION_CHECK(2,1,0)
#  define _DAI_DIAGNOSTIC_DISABLE_DEPRECATED _Pragma("diag_suppress 1291,1718")
#elif _DAI_SUNPRO_VERSION_CHECK(5,13,0) && !defined(__cplusplus)
#  define _DAI_DIAGNOSTIC_DISABLE_DEPRECATED _Pragma("error_messages(off,E_DEPRECATED_ATT,E_DEPRECATED_ATT_MESS)")
#elif _DAI_SUNPRO_VERSION_CHECK(5,13,0) && defined(__cplusplus)
#  define _DAI_DIAGNOSTIC_DISABLE_DEPRECATED _Pragma("error_messages(off,symdeprecated,symdeprecated2)")
#elif _DAI_IAR_VERSION_CHECK(8,0,0)
#  define _DAI_DIAGNOSTIC_DISABLE_DEPRECATED _Pragma("diag_suppress=Pe1444,Pe1215")
#elif _DAI_PELLES_VERSION_CHECK(2,90,0)
#  define _DAI_DIAGNOSTIC_DISABLE_DEPRECATED _Pragma("warn(disable:2241)")
#else
#  define _DAI_DIAGNOSTIC_DISABLE_DEPRECATED
#endif

#if defined(_DAI_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS)
#  undef _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS
#endif
#if _DAI_HAS_WARNING("-Wunknown-pragmas")
#  define _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS _Pragma("clang diagnostic ignored \"-Wunknown-pragmas\"")
#elif _DAI_INTEL_VERSION_CHECK(13,0,0)
#  define _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS _Pragma("warning(disable:161)")
#elif _DAI_INTEL_CL_VERSION_CHECK(2021,1,0)
#  define _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS __pragma(warning(disable:161))
#elif _DAI_PGI_VERSION_CHECK(17,10,0)
#  define _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS _Pragma("diag_suppress 1675")
#elif _DAI_GCC_VERSION_CHECK(4,3,0)
#  define _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS _Pragma("GCC diagnostic ignored \"-Wunknown-pragmas\"")
#elif _DAI_MSVC_VERSION_CHECK(15,0,0)
#  define _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS __pragma(warning(disable:4068))
#elif \
    _DAI_TI_VERSION_CHECK(16,9,0) || \
    _DAI_TI_CL6X_VERSION_CHECK(8,0,0) || \
    _DAI_TI_CL7X_VERSION_CHECK(1,2,0) || \
    _DAI_TI_CLPRU_VERSION_CHECK(2,3,0)
#  define _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS _Pragma("diag_suppress 163")
#elif _DAI_TI_CL6X_VERSION_CHECK(8,0,0)
#  define _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS _Pragma("diag_suppress 163")
#elif _DAI_IAR_VERSION_CHECK(8,0,0)
#  define _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS _Pragma("diag_suppress=Pe161")
#elif _DAI_MCST_LCC_VERSION_CHECK(1,25,10)
#  define _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS _Pragma("diag_suppress 161")
#else
#  define _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS
#endif

#if defined(_DAI_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES)
#  undef _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES
#endif
#if _DAI_HAS_WARNING("-Wunknown-attributes")
#  define _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES _Pragma("clang diagnostic ignored \"-Wunknown-attributes\"")
#elif _DAI_GCC_VERSION_CHECK(4,6,0)
#  define _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")
#elif _DAI_INTEL_VERSION_CHECK(17,0,0)
#  define _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES _Pragma("warning(disable:1292)")
#elif _DAI_INTEL_CL_VERSION_CHECK(2021,1,0)
#  define _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES __pragma(warning(disable:1292))
#elif _DAI_MSVC_VERSION_CHECK(19,0,0)
#  define _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES __pragma(warning(disable:5030))
#elif _DAI_PGI_VERSION_CHECK(20,7,0)
#  define _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES _Pragma("diag_suppress 1097,1098")
#elif _DAI_PGI_VERSION_CHECK(17,10,0)
#  define _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES _Pragma("diag_suppress 1097")
#elif _DAI_SUNPRO_VERSION_CHECK(5,14,0) && defined(__cplusplus)
#  define _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES _Pragma("error_messages(off,attrskipunsup)")
#elif \
    _DAI_TI_VERSION_CHECK(18,1,0) || \
    _DAI_TI_CL6X_VERSION_CHECK(8,3,0) || \
    _DAI_TI_CL7X_VERSION_CHECK(1,2,0)
#  define _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES _Pragma("diag_suppress 1173")
#elif _DAI_IAR_VERSION_CHECK(8,0,0)
#  define _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES _Pragma("diag_suppress=Pe1097")
#elif _DAI_MCST_LCC_VERSION_CHECK(1,25,10)
#  define _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES _Pragma("diag_suppress 1097")
#else
#  define _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES
#endif

#if defined(_DAI_DIAGNOSTIC_DISABLE_CAST_QUAL)
#  undef _DAI_DIAGNOSTIC_DISABLE_CAST_QUAL
#endif
#if _DAI_HAS_WARNING("-Wcast-qual")
#  define _DAI_DIAGNOSTIC_DISABLE_CAST_QUAL _Pragma("clang diagnostic ignored \"-Wcast-qual\"")
#elif _DAI_INTEL_VERSION_CHECK(13,0,0)
#  define _DAI_DIAGNOSTIC_DISABLE_CAST_QUAL _Pragma("warning(disable:2203 2331)")
#elif _DAI_GCC_VERSION_CHECK(3,0,0)
#  define _DAI_DIAGNOSTIC_DISABLE_CAST_QUAL _Pragma("GCC diagnostic ignored \"-Wcast-qual\"")
#else
#  define _DAI_DIAGNOSTIC_DISABLE_CAST_QUAL
#endif

#if defined(_DAI_DIAGNOSTIC_DISABLE_UNUSED_FUNCTION)
#  undef _DAI_DIAGNOSTIC_DISABLE_UNUSED_FUNCTION
#endif
#if _DAI_HAS_WARNING("-Wunused-function")
#  define _DAI_DIAGNOSTIC_DISABLE_UNUSED_FUNCTION _Pragma("clang diagnostic ignored \"-Wunused-function\"")
#elif _DAI_GCC_VERSION_CHECK(3,4,0)
#  define _DAI_DIAGNOSTIC_DISABLE_UNUSED_FUNCTION _Pragma("GCC diagnostic ignored \"-Wunused-function\"")
#elif _DAI_MSVC_VERSION_CHECK(1,0,0)
#  define _DAI_DIAGNOSTIC_DISABLE_UNUSED_FUNCTION __pragma(warning(disable:4505))
#elif _DAI_MCST_LCC_VERSION_CHECK(1,25,10)
#  define _DAI_DIAGNOSTIC_DISABLE_UNUSED_FUNCTION _Pragma("diag_suppress 3142")
#else
#  define _DAI_DIAGNOSTIC_DISABLE_UNUSED_FUNCTION
#endif

#if defined(_DAI_DEPRECATED)
#  undef _DAI_DEPRECATED
#endif
#if defined(_DAI_DEPRECATED_FOR)
#  undef _DAI_DEPRECATED_FOR
#endif
#if \
  _DAI_MSVC_VERSION_CHECK(14,0,0) || \
  _DAI_INTEL_CL_VERSION_CHECK(2021,1,0)
#  define _DAI_DEPRECATED(since) __declspec(deprecated("Since " # since))
#  define _DAI_DEPRECATED_FOR(since, replacement) __declspec(deprecated("Since " #since "; use " #replacement))
#elif \
  (_DAI_HAS_EXTENSION(attribute_deprecated_with_message) && !defined(_DAI_IAR_VERSION)) || \
  _DAI_GCC_VERSION_CHECK(4,5,0) || \
  _DAI_INTEL_VERSION_CHECK(13,0,0) || \
  _DAI_ARM_VERSION_CHECK(5,6,0) || \
  _DAI_SUNPRO_VERSION_CHECK(5,13,0) || \
  _DAI_PGI_VERSION_CHECK(17,10,0) || \
  _DAI_TI_VERSION_CHECK(18,1,0) || \
  _DAI_TI_ARMCL_VERSION_CHECK(18,1,0) || \
  _DAI_TI_CL6X_VERSION_CHECK(8,3,0) || \
  _DAI_TI_CL7X_VERSION_CHECK(1,2,0) || \
  _DAI_TI_CLPRU_VERSION_CHECK(2,3,0) || \
  _DAI_MCST_LCC_VERSION_CHECK(1,25,10)
#  define _DAI_DEPRECATED(since) __attribute__((__deprecated__("Since " #since)))
#  define _DAI_DEPRECATED_FOR(since, replacement) __attribute__((__deprecated__("Since " #since "; use " #replacement)))
#elif defined(__cplusplus) && (__cplusplus >= 201402L)
#  define _DAI_DEPRECATED(since) _DAI_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_([[deprecated("Since " #since)]])
#  define _DAI_DEPRECATED_FOR(since, replacement) _DAI_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_([[deprecated("Since " #since "; use " #replacement)]])
#elif \
  _DAI_HAS_ATTRIBUTE(deprecated) || \
  _DAI_GCC_VERSION_CHECK(3,1,0) || \
  _DAI_ARM_VERSION_CHECK(4,1,0) || \
  _DAI_TI_VERSION_CHECK(15,12,0) || \
  (_DAI_TI_ARMCL_VERSION_CHECK(4,8,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_ARMCL_VERSION_CHECK(5,2,0) || \
  (_DAI_TI_CL2000_VERSION_CHECK(6,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL2000_VERSION_CHECK(6,4,0) || \
  (_DAI_TI_CL430_VERSION_CHECK(4,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL430_VERSION_CHECK(4,3,0) || \
  (_DAI_TI_CL6X_VERSION_CHECK(7,2,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL6X_VERSION_CHECK(7,5,0) || \
  _DAI_TI_CL7X_VERSION_CHECK(1,2,0) || \
  _DAI_TI_CLPRU_VERSION_CHECK(2,1,0) || \
  _DAI_MCST_LCC_VERSION_CHECK(1,25,10) || \
  _DAI_IAR_VERSION_CHECK(8,10,0)
#  define _DAI_DEPRECATED(since) __attribute__((__deprecated__))
#  define _DAI_DEPRECATED_FOR(since, replacement) __attribute__((__deprecated__))
#elif \
  _DAI_MSVC_VERSION_CHECK(13,10,0) || \
  _DAI_PELLES_VERSION_CHECK(6,50,0) || \
  _DAI_INTEL_CL_VERSION_CHECK(2021,1,0)
#  define _DAI_DEPRECATED(since) __declspec(deprecated)
#  define _DAI_DEPRECATED_FOR(since, replacement) __declspec(deprecated)
#elif _DAI_IAR_VERSION_CHECK(8,0,0)
#  define _DAI_DEPRECATED(since) _Pragma("deprecated")
#  define _DAI_DEPRECATED_FOR(since, replacement) _Pragma("deprecated")
#else
#  define _DAI_DEPRECATED(since)
#  define _DAI_DEPRECATED_FOR(since, replacement)
#endif

#if defined(_DAI_UNAVAILABLE)
#  undef _DAI_UNAVAILABLE
#endif
#if \
  _DAI_HAS_ATTRIBUTE(warning) || \
  _DAI_GCC_VERSION_CHECK(4,3,0) || \
  _DAI_INTEL_VERSION_CHECK(13,0,0) || \
  _DAI_MCST_LCC_VERSION_CHECK(1,25,10)
#  define _DAI_UNAVAILABLE(available_since) __attribute__((__warning__("Not available until " #available_since)))
#else
#  define _DAI_UNAVAILABLE(available_since)
#endif

#if defined(_DAI_WARN_UNUSED_RESULT)
#  undef _DAI_WARN_UNUSED_RESULT
#endif
#if defined(_DAI_WARN_UNUSED_RESULT_MSG)
#  undef _DAI_WARN_UNUSED_RESULT_MSG
#endif
#if \
  _DAI_HAS_ATTRIBUTE(warn_unused_result) || \
  _DAI_GCC_VERSION_CHECK(3,4,0) || \
  _DAI_INTEL_VERSION_CHECK(13,0,0) || \
  _DAI_TI_VERSION_CHECK(15,12,0) || \
  (_DAI_TI_ARMCL_VERSION_CHECK(4,8,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_ARMCL_VERSION_CHECK(5,2,0) || \
  (_DAI_TI_CL2000_VERSION_CHECK(6,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL2000_VERSION_CHECK(6,4,0) || \
  (_DAI_TI_CL430_VERSION_CHECK(4,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL430_VERSION_CHECK(4,3,0) || \
  (_DAI_TI_CL6X_VERSION_CHECK(7,2,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL6X_VERSION_CHECK(7,5,0) || \
  _DAI_TI_CL7X_VERSION_CHECK(1,2,0) || \
  _DAI_TI_CLPRU_VERSION_CHECK(2,1,0) || \
  (_DAI_SUNPRO_VERSION_CHECK(5,15,0) && defined(__cplusplus)) || \
  _DAI_PGI_VERSION_CHECK(17,10,0) || \
  _DAI_MCST_LCC_VERSION_CHECK(1,25,10)
#  define _DAI_WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))
#  define _DAI_WARN_UNUSED_RESULT_MSG(msg) __attribute__((__warn_unused_result__))
#elif (_DAI_HAS_CPP_ATTRIBUTE(nodiscard) >= 201907L)
#  define _DAI_WARN_UNUSED_RESULT _DAI_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_([[nodiscard]])
#  define _DAI_WARN_UNUSED_RESULT_MSG(msg) _DAI_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_([[nodiscard(msg)]])
#elif _DAI_HAS_CPP_ATTRIBUTE(nodiscard)
#  define _DAI_WARN_UNUSED_RESULT _DAI_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_([[nodiscard]])
#  define _DAI_WARN_UNUSED_RESULT_MSG(msg) _DAI_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_([[nodiscard]])
#elif defined(_Check_return_) /* SAL */
#  define _DAI_WARN_UNUSED_RESULT _Check_return_
#  define _DAI_WARN_UNUSED_RESULT_MSG(msg) _Check_return_
#else
#  define _DAI_WARN_UNUSED_RESULT
#  define _DAI_WARN_UNUSED_RESULT_MSG(msg)
#endif

#if defined(_DAI_SENTINEL)
#  undef _DAI_SENTINEL
#endif
#if \
  _DAI_HAS_ATTRIBUTE(sentinel) || \
  _DAI_GCC_VERSION_CHECK(4,0,0) || \
  _DAI_INTEL_VERSION_CHECK(13,0,0) || \
  _DAI_ARM_VERSION_CHECK(5,4,0) || \
  _DAI_MCST_LCC_VERSION_CHECK(1,25,10)
#  define _DAI_SENTINEL(position) __attribute__((__sentinel__(position)))
#else
#  define _DAI_SENTINEL(position)
#endif

#if defined(_DAI_NO_RETURN)
#  undef _DAI_NO_RETURN
#endif
#if _DAI_IAR_VERSION_CHECK(8,0,0)
#  define _DAI_NO_RETURN __noreturn
#elif \
  _DAI_INTEL_VERSION_CHECK(13,0,0) || \
  _DAI_MCST_LCC_VERSION_CHECK(1,25,10)
#  define _DAI_NO_RETURN __attribute__((__noreturn__))
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#  define _DAI_NO_RETURN _Noreturn
#elif defined(__cplusplus) && (__cplusplus >= 201103L)
#  define _DAI_NO_RETURN _DAI_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_([[noreturn]])
#elif \
  _DAI_HAS_ATTRIBUTE(noreturn) || \
  _DAI_GCC_VERSION_CHECK(3,2,0) || \
  _DAI_SUNPRO_VERSION_CHECK(5,11,0) || \
  _DAI_ARM_VERSION_CHECK(4,1,0) || \
  _DAI_IBM_VERSION_CHECK(10,1,0) || \
  _DAI_TI_VERSION_CHECK(15,12,0) || \
  (_DAI_TI_ARMCL_VERSION_CHECK(4,8,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_ARMCL_VERSION_CHECK(5,2,0) || \
  (_DAI_TI_CL2000_VERSION_CHECK(6,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL2000_VERSION_CHECK(6,4,0) || \
  (_DAI_TI_CL430_VERSION_CHECK(4,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL430_VERSION_CHECK(4,3,0) || \
  (_DAI_TI_CL6X_VERSION_CHECK(7,2,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL6X_VERSION_CHECK(7,5,0) || \
  _DAI_TI_CL7X_VERSION_CHECK(1,2,0) || \
  _DAI_TI_CLPRU_VERSION_CHECK(2,1,0) || \
  _DAI_IAR_VERSION_CHECK(8,10,0)
#  define _DAI_NO_RETURN __attribute__((__noreturn__))
#elif _DAI_SUNPRO_VERSION_CHECK(5,10,0)
#  define _DAI_NO_RETURN _Pragma("does_not_return")
#elif \
  _DAI_MSVC_VERSION_CHECK(13,10,0) || \
  _DAI_INTEL_CL_VERSION_CHECK(2021,1,0)
#  define _DAI_NO_RETURN __declspec(noreturn)
#elif _DAI_TI_CL6X_VERSION_CHECK(6,0,0) && defined(__cplusplus)
#  define _DAI_NO_RETURN _Pragma("FUNC_NEVER_RETURNS;")
#elif _DAI_COMPCERT_VERSION_CHECK(3,2,0)
#  define _DAI_NO_RETURN __attribute((noreturn))
#elif _DAI_PELLES_VERSION_CHECK(9,0,0)
#  define _DAI_NO_RETURN __declspec(noreturn)
#else
#  define _DAI_NO_RETURN
#endif

#if defined(_DAI_NO_ESCAPE)
#  undef _DAI_NO_ESCAPE
#endif
#if _DAI_HAS_ATTRIBUTE(noescape)
#  define _DAI_NO_ESCAPE __attribute__((__noescape__))
#else
#  define _DAI_NO_ESCAPE
#endif

#if defined(_DAI_UNREACHABLE)
#  undef _DAI_UNREACHABLE
#endif
#if defined(_DAI_UNREACHABLE_RETURN)
#  undef _DAI_UNREACHABLE_RETURN
#endif
#if defined(_DAI_ASSUME)
#  undef _DAI_ASSUME
#endif
#if \
  _DAI_MSVC_VERSION_CHECK(13,10,0) || \
  _DAI_INTEL_VERSION_CHECK(13,0,0) || \
  _DAI_INTEL_CL_VERSION_CHECK(2021,1,0)
#  define _DAI_ASSUME(expr) __assume(expr)
#elif _DAI_HAS_BUILTIN(__builtin_assume)
#  define _DAI_ASSUME(expr) __builtin_assume(expr)
#elif \
    _DAI_TI_CL2000_VERSION_CHECK(6,2,0) || \
    _DAI_TI_CL6X_VERSION_CHECK(4,0,0)
#  if defined(__cplusplus)
#    define _DAI_ASSUME(expr) std::_nassert(expr)
#  else
#    define _DAI_ASSUME(expr) _nassert(expr)
#  endif
#endif
#if \
  (_DAI_HAS_BUILTIN(__builtin_unreachable) && (!defined(_DAI_ARM_VERSION))) || \
  _DAI_GCC_VERSION_CHECK(4,5,0) || \
  _DAI_PGI_VERSION_CHECK(18,10,0) || \
  _DAI_INTEL_VERSION_CHECK(13,0,0) || \
  _DAI_IBM_VERSION_CHECK(13,1,5) || \
  _DAI_CRAY_VERSION_CHECK(10,0,0) || \
  _DAI_MCST_LCC_VERSION_CHECK(1,25,10)
#  define _DAI_UNREACHABLE() __builtin_unreachable()
#elif defined(_DAI_ASSUME)
#  define _DAI_UNREACHABLE() _DAI_ASSUME(0)
#endif
#if !defined(_DAI_ASSUME)
#  if defined(_DAI_UNREACHABLE)
#    define _DAI_ASSUME(expr) _DAI_STATIC_CAST(void, ((expr) ? 1 : (_DAI_UNREACHABLE(), 1)))
#  else
#    define _DAI_ASSUME(expr) _DAI_STATIC_CAST(void, expr)
#  endif
#endif
#if defined(_DAI_UNREACHABLE)
#  if  \
      _DAI_TI_CL2000_VERSION_CHECK(6,2,0) || \
      _DAI_TI_CL6X_VERSION_CHECK(4,0,0)
#    define _DAI_UNREACHABLE_RETURN(value) return (_DAI_STATIC_CAST(void, _DAI_ASSUME(0)), (value))
#  else
#    define _DAI_UNREACHABLE_RETURN(value) _DAI_UNREACHABLE()
#  endif
#else
#  define _DAI_UNREACHABLE_RETURN(value) return (value)
#endif
#if !defined(_DAI_UNREACHABLE)
#  define _DAI_UNREACHABLE() _DAI_ASSUME(0)
#endif

_DAI_DIAGNOSTIC_PUSH
#if _DAI_HAS_WARNING("-Wpedantic")
#  pragma clang diagnostic ignored "-Wpedantic"
#endif
#if _DAI_HAS_WARNING("-Wc++98-compat-pedantic") && defined(__cplusplus)
#  pragma clang diagnostic ignored "-Wc++98-compat-pedantic"
#endif
#if _DAI_GCC_HAS_WARNING("-Wvariadic-macros",4,0,0)
#  if defined(__clang__)
#    pragma clang diagnostic ignored "-Wvariadic-macros"
#  elif defined(_DAI_GCC_VERSION)
#    pragma GCC diagnostic ignored "-Wvariadic-macros"
#  endif
#endif
#if defined(_DAI_NON_NULL)
#  undef _DAI_NON_NULL
#endif
#if \
  _DAI_HAS_ATTRIBUTE(nonnull) || \
  _DAI_GCC_VERSION_CHECK(3,3,0) || \
  _DAI_INTEL_VERSION_CHECK(13,0,0) || \
  _DAI_ARM_VERSION_CHECK(4,1,0)
#  define _DAI_NON_NULL(...) __attribute__((__nonnull__(__VA_ARGS__)))
#else
#  define _DAI_NON_NULL(...)
#endif
_DAI_DIAGNOSTIC_POP

#if defined(_DAI_PRINTF_FORMAT)
#  undef _DAI_PRINTF_FORMAT
#endif
#if defined(__MINGW32__) && _DAI_GCC_HAS_ATTRIBUTE(format,4,4,0) && !defined(__USE_MINGW_ANSI_STDIO)
#  define _DAI_PRINTF_FORMAT(string_idx,first_to_check) __attribute__((__format__(ms_printf, string_idx, first_to_check)))
#elif defined(__MINGW32__) && _DAI_GCC_HAS_ATTRIBUTE(format,4,4,0) && defined(__USE_MINGW_ANSI_STDIO)
#  define _DAI_PRINTF_FORMAT(string_idx,first_to_check) __attribute__((__format__(gnu_printf, string_idx, first_to_check)))
#elif \
  _DAI_HAS_ATTRIBUTE(format) || \
  _DAI_GCC_VERSION_CHECK(3,1,0) || \
  _DAI_INTEL_VERSION_CHECK(13,0,0) || \
  _DAI_ARM_VERSION_CHECK(5,6,0) || \
  _DAI_IBM_VERSION_CHECK(10,1,0) || \
  _DAI_TI_VERSION_CHECK(15,12,0) || \
  (_DAI_TI_ARMCL_VERSION_CHECK(4,8,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_ARMCL_VERSION_CHECK(5,2,0) || \
  (_DAI_TI_CL2000_VERSION_CHECK(6,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL2000_VERSION_CHECK(6,4,0) || \
  (_DAI_TI_CL430_VERSION_CHECK(4,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL430_VERSION_CHECK(4,3,0) || \
  (_DAI_TI_CL6X_VERSION_CHECK(7,2,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL6X_VERSION_CHECK(7,5,0) || \
  _DAI_TI_CL7X_VERSION_CHECK(1,2,0) || \
  _DAI_TI_CLPRU_VERSION_CHECK(2,1,0) || \
  _DAI_MCST_LCC_VERSION_CHECK(1,25,10)
#  define _DAI_PRINTF_FORMAT(string_idx,first_to_check) __attribute__((__format__(__printf__, string_idx, first_to_check)))
#elif _DAI_PELLES_VERSION_CHECK(6,0,0)
#  define _DAI_PRINTF_FORMAT(string_idx,first_to_check) __declspec(vaformat(printf,string_idx,first_to_check))
#else
#  define _DAI_PRINTF_FORMAT(string_idx,first_to_check)
#endif

#if defined(_DAI_CONSTEXPR)
#  undef _DAI_CONSTEXPR
#endif
#if defined(__cplusplus)
#  if __cplusplus >= 201103L
#    define _DAI_CONSTEXPR _DAI_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_(constexpr)
#  endif
#endif
#if !defined(_DAI_CONSTEXPR)
#  define _DAI_CONSTEXPR
#endif

#if defined(_DAI_PREDICT)
#  undef _DAI_PREDICT
#endif
#if defined(_DAI_LIKELY)
#  undef _DAI_LIKELY
#endif
#if defined(_DAI_UNLIKELY)
#  undef _DAI_UNLIKELY
#endif
#if defined(_DAI_UNPREDICTABLE)
#  undef _DAI_UNPREDICTABLE
#endif
#if _DAI_HAS_BUILTIN(__builtin_unpredictable)
#  define _DAI_UNPREDICTABLE(expr) __builtin_unpredictable((expr))
#endif
#if \
  (_DAI_HAS_BUILTIN(__builtin_expect_with_probability) && !defined(_DAI_PGI_VERSION)) || \
  _DAI_GCC_VERSION_CHECK(9,0,0) || \
  _DAI_MCST_LCC_VERSION_CHECK(1,25,10)
#  define _DAI_PREDICT(expr, value, probability) __builtin_expect_with_probability(  (expr), (value), (probability))
#  define _DAI_PREDICT_TRUE(expr, probability)   __builtin_expect_with_probability(!!(expr),    1   , (probability))
#  define _DAI_PREDICT_FALSE(expr, probability)  __builtin_expect_with_probability(!!(expr),    0   , (probability))
#  define _DAI_LIKELY(expr)                      __builtin_expect                 (!!(expr),    1                  )
#  define _DAI_UNLIKELY(expr)                    __builtin_expect                 (!!(expr),    0                  )
#elif \
  (_DAI_HAS_BUILTIN(__builtin_expect) && !defined(_DAI_INTEL_CL_VERSION)) || \
  _DAI_GCC_VERSION_CHECK(3,0,0) || \
  _DAI_INTEL_VERSION_CHECK(13,0,0) || \
  (_DAI_SUNPRO_VERSION_CHECK(5,15,0) && defined(__cplusplus)) || \
  _DAI_ARM_VERSION_CHECK(4,1,0) || \
  _DAI_IBM_VERSION_CHECK(10,1,0) || \
  _DAI_TI_VERSION_CHECK(15,12,0) || \
  _DAI_TI_ARMCL_VERSION_CHECK(4,7,0) || \
  _DAI_TI_CL430_VERSION_CHECK(3,1,0) || \
  _DAI_TI_CL2000_VERSION_CHECK(6,1,0) || \
  _DAI_TI_CL6X_VERSION_CHECK(6,1,0) || \
  _DAI_TI_CL7X_VERSION_CHECK(1,2,0) || \
  _DAI_TI_CLPRU_VERSION_CHECK(2,1,0) || \
  _DAI_TINYC_VERSION_CHECK(0,9,27) || \
  _DAI_CRAY_VERSION_CHECK(8,1,0) || \
  _DAI_MCST_LCC_VERSION_CHECK(1,25,10)
#  define _DAI_PREDICT(expr, expected, probability) \
     (((probability) >= 0.9) ? __builtin_expect((expr), (expected)) : (_DAI_STATIC_CAST(void, expected), (expr)))
#  define _DAI_PREDICT_TRUE(expr, probability) \
     (__extension__ ({ \
       double _DAI_probability_ = (probability); \
       ((_DAI_probability_ >= 0.9) ? __builtin_expect(!!(expr), 1) : ((_DAI_probability_ <= 0.1) ? __builtin_expect(!!(expr), 0) : !!(expr))); \
     }))
#  define _DAI_PREDICT_FALSE(expr, probability) \
     (__extension__ ({ \
       double _DAI_probability_ = (probability); \
       ((_DAI_probability_ >= 0.9) ? __builtin_expect(!!(expr), 0) : ((_DAI_probability_ <= 0.1) ? __builtin_expect(!!(expr), 1) : !!(expr))); \
     }))
#  define _DAI_LIKELY(expr)   __builtin_expect(!!(expr), 1)
#  define _DAI_UNLIKELY(expr) __builtin_expect(!!(expr), 0)
#else
#  define _DAI_PREDICT(expr, expected, probability) (_DAI_STATIC_CAST(void, expected), (expr))
#  define _DAI_PREDICT_TRUE(expr, probability) (!!(expr))
#  define _DAI_PREDICT_FALSE(expr, probability) (!!(expr))
#  define _DAI_LIKELY(expr) (!!(expr))
#  define _DAI_UNLIKELY(expr) (!!(expr))
#endif
#if !defined(_DAI_UNPREDICTABLE)
#  define _DAI_UNPREDICTABLE(expr) _DAI_PREDICT(expr, 1, 0.5)
#endif

#if defined(_DAI_MALLOC_ATTR)
#  undef _DAI_MALLOC_ATTR
#endif
#if \
  _DAI_HAS_ATTRIBUTE(malloc) || \
  _DAI_GCC_VERSION_CHECK(3,1,0) || \
  _DAI_INTEL_VERSION_CHECK(13,0,0) || \
  _DAI_SUNPRO_VERSION_CHECK(5,11,0) || \
  _DAI_ARM_VERSION_CHECK(4,1,0) || \
  _DAI_IBM_VERSION_CHECK(12,1,0) || \
  _DAI_TI_VERSION_CHECK(15,12,0) || \
  (_DAI_TI_ARMCL_VERSION_CHECK(4,8,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_ARMCL_VERSION_CHECK(5,2,0) || \
  (_DAI_TI_CL2000_VERSION_CHECK(6,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL2000_VERSION_CHECK(6,4,0) || \
  (_DAI_TI_CL430_VERSION_CHECK(4,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL430_VERSION_CHECK(4,3,0) || \
  (_DAI_TI_CL6X_VERSION_CHECK(7,2,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL6X_VERSION_CHECK(7,5,0) || \
  _DAI_TI_CL7X_VERSION_CHECK(1,2,0) || \
  _DAI_TI_CLPRU_VERSION_CHECK(2,1,0) || \
  _DAI_MCST_LCC_VERSION_CHECK(1,25,10)
#  define _DAI_MALLOC_ATTR __attribute__((__malloc__))
#elif _DAI_SUNPRO_VERSION_CHECK(5,10,0)
#  define _DAI_MALLOC_ATTR _Pragma("returns_new_memory")
#elif \
  _DAI_MSVC_VERSION_CHECK(14,0,0) || \
  _DAI_INTEL_CL_VERSION_CHECK(2021,1,0)
#  define _DAI_MALLOC_ATTR __declspec(restrict)
#else
#  define _DAI_MALLOC_ATTR
#endif

#if defined(_DAI_PURE)
#  undef _DAI_PURE
#endif
#if \
  _DAI_HAS_ATTRIBUTE(pure) || \
  _DAI_GCC_VERSION_CHECK(2,96,0) || \
  _DAI_INTEL_VERSION_CHECK(13,0,0) || \
  _DAI_SUNPRO_VERSION_CHECK(5,11,0) || \
  _DAI_ARM_VERSION_CHECK(4,1,0) || \
  _DAI_IBM_VERSION_CHECK(10,1,0) || \
  _DAI_TI_VERSION_CHECK(15,12,0) || \
  (_DAI_TI_ARMCL_VERSION_CHECK(4,8,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_ARMCL_VERSION_CHECK(5,2,0) || \
  (_DAI_TI_CL2000_VERSION_CHECK(6,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL2000_VERSION_CHECK(6,4,0) || \
  (_DAI_TI_CL430_VERSION_CHECK(4,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL430_VERSION_CHECK(4,3,0) || \
  (_DAI_TI_CL6X_VERSION_CHECK(7,2,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL6X_VERSION_CHECK(7,5,0) || \
  _DAI_TI_CL7X_VERSION_CHECK(1,2,0) || \
  _DAI_TI_CLPRU_VERSION_CHECK(2,1,0) || \
  _DAI_PGI_VERSION_CHECK(17,10,0) || \
  _DAI_MCST_LCC_VERSION_CHECK(1,25,10)
#  define _DAI_PURE __attribute__((__pure__))
#elif _DAI_SUNPRO_VERSION_CHECK(5,10,0)
#  define _DAI_PURE _Pragma("does_not_write_global_data")
#elif defined(__cplusplus) && \
    ( \
      _DAI_TI_CL430_VERSION_CHECK(2,0,1) || \
      _DAI_TI_CL6X_VERSION_CHECK(4,0,0) || \
      _DAI_TI_CL7X_VERSION_CHECK(1,2,0) \
    )
#  define _DAI_PURE _Pragma("FUNC_IS_PURE;")
#else
#  define _DAI_PURE
#endif

#if defined(_DAI_CONST)
#  undef _DAI_CONST
#endif
#if \
  _DAI_HAS_ATTRIBUTE(const) || \
  _DAI_GCC_VERSION_CHECK(2,5,0) || \
  _DAI_INTEL_VERSION_CHECK(13,0,0) || \
  _DAI_SUNPRO_VERSION_CHECK(5,11,0) || \
  _DAI_ARM_VERSION_CHECK(4,1,0) || \
  _DAI_IBM_VERSION_CHECK(10,1,0) || \
  _DAI_TI_VERSION_CHECK(15,12,0) || \
  (_DAI_TI_ARMCL_VERSION_CHECK(4,8,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_ARMCL_VERSION_CHECK(5,2,0) || \
  (_DAI_TI_CL2000_VERSION_CHECK(6,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL2000_VERSION_CHECK(6,4,0) || \
  (_DAI_TI_CL430_VERSION_CHECK(4,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL430_VERSION_CHECK(4,3,0) || \
  (_DAI_TI_CL6X_VERSION_CHECK(7,2,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL6X_VERSION_CHECK(7,5,0) || \
  _DAI_TI_CL7X_VERSION_CHECK(1,2,0) || \
  _DAI_TI_CLPRU_VERSION_CHECK(2,1,0) || \
  _DAI_PGI_VERSION_CHECK(17,10,0) || \
  _DAI_MCST_LCC_VERSION_CHECK(1,25,10)
#  define _DAI_CONST __attribute__((__const__))
#elif \
  _DAI_SUNPRO_VERSION_CHECK(5,10,0)
#  define _DAI_CONST _Pragma("no_side_effect")
#else
#  define _DAI_CONST _DAI_PURE
#endif

#if defined(_DAI_RESTRICT)
#  undef _DAI_RESTRICT
#endif
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L) && !defined(__cplusplus)
#  define _DAI_RESTRICT restrict
#elif \
  _DAI_GCC_VERSION_CHECK(3,1,0) || \
  _DAI_MSVC_VERSION_CHECK(14,0,0) || \
  _DAI_INTEL_VERSION_CHECK(13,0,0) || \
  _DAI_INTEL_CL_VERSION_CHECK(2021,1,0) || \
  _DAI_ARM_VERSION_CHECK(4,1,0) || \
  _DAI_IBM_VERSION_CHECK(10,1,0) || \
  _DAI_PGI_VERSION_CHECK(17,10,0) || \
  _DAI_TI_CL430_VERSION_CHECK(4,3,0) || \
  _DAI_TI_CL2000_VERSION_CHECK(6,2,4) || \
  _DAI_TI_CL6X_VERSION_CHECK(8,1,0) || \
  _DAI_TI_CL7X_VERSION_CHECK(1,2,0) || \
  (_DAI_SUNPRO_VERSION_CHECK(5,14,0) && defined(__cplusplus)) || \
  _DAI_IAR_VERSION_CHECK(8,0,0) || \
  defined(__clang__) || \
  _DAI_MCST_LCC_VERSION_CHECK(1,25,10)
#  define _DAI_RESTRICT __restrict
#elif _DAI_SUNPRO_VERSION_CHECK(5,3,0) && !defined(__cplusplus)
#  define _DAI_RESTRICT _Restrict
#else
#  define _DAI_RESTRICT
#endif

#if defined(_DAI_INLINE)
#  undef _DAI_INLINE
#endif
#if \
  (defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)) || \
  (defined(__cplusplus) && (__cplusplus >= 199711L))
#  define _DAI_INLINE inline
#elif \
  defined(_DAI_GCC_VERSION) || \
  _DAI_ARM_VERSION_CHECK(6,2,0)
#  define _DAI_INLINE __inline__
#elif \
  _DAI_MSVC_VERSION_CHECK(12,0,0) || \
  _DAI_INTEL_CL_VERSION_CHECK(2021,1,0) || \
  _DAI_ARM_VERSION_CHECK(4,1,0) || \
  _DAI_TI_ARMCL_VERSION_CHECK(5,1,0) || \
  _DAI_TI_CL430_VERSION_CHECK(3,1,0) || \
  _DAI_TI_CL2000_VERSION_CHECK(6,2,0) || \
  _DAI_TI_CL6X_VERSION_CHECK(8,0,0) || \
  _DAI_TI_CL7X_VERSION_CHECK(1,2,0) || \
  _DAI_TI_CLPRU_VERSION_CHECK(2,1,0) || \
  _DAI_MCST_LCC_VERSION_CHECK(1,25,10)
#  define _DAI_INLINE __inline
#else
#  define _DAI_INLINE
#endif

#if defined(_DAI_ALWAYS_INLINE)
#  undef _DAI_ALWAYS_INLINE
#endif
#if \
  _DAI_HAS_ATTRIBUTE(always_inline) || \
  _DAI_GCC_VERSION_CHECK(4,0,0) || \
  _DAI_INTEL_VERSION_CHECK(13,0,0) || \
  _DAI_SUNPRO_VERSION_CHECK(5,11,0) || \
  _DAI_ARM_VERSION_CHECK(4,1,0) || \
  _DAI_IBM_VERSION_CHECK(10,1,0) || \
  _DAI_TI_VERSION_CHECK(15,12,0) || \
  (_DAI_TI_ARMCL_VERSION_CHECK(4,8,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_ARMCL_VERSION_CHECK(5,2,0) || \
  (_DAI_TI_CL2000_VERSION_CHECK(6,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL2000_VERSION_CHECK(6,4,0) || \
  (_DAI_TI_CL430_VERSION_CHECK(4,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL430_VERSION_CHECK(4,3,0) || \
  (_DAI_TI_CL6X_VERSION_CHECK(7,2,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL6X_VERSION_CHECK(7,5,0) || \
  _DAI_TI_CL7X_VERSION_CHECK(1,2,0) || \
  _DAI_TI_CLPRU_VERSION_CHECK(2,1,0) || \
  _DAI_MCST_LCC_VERSION_CHECK(1,25,10) || \
  _DAI_IAR_VERSION_CHECK(8,10,0)
#  define _DAI_ALWAYS_INLINE __attribute__((__always_inline__)) _DAI_INLINE
#elif \
  _DAI_MSVC_VERSION_CHECK(12,0,0) || \
  _DAI_INTEL_CL_VERSION_CHECK(2021,1,0)
#  define _DAI_ALWAYS_INLINE __forceinline
#elif defined(__cplusplus) && \
    ( \
      _DAI_TI_ARMCL_VERSION_CHECK(5,2,0) || \
      _DAI_TI_CL430_VERSION_CHECK(4,3,0) || \
      _DAI_TI_CL2000_VERSION_CHECK(6,4,0) || \
      _DAI_TI_CL6X_VERSION_CHECK(6,1,0) || \
      _DAI_TI_CL7X_VERSION_CHECK(1,2,0) || \
      _DAI_TI_CLPRU_VERSION_CHECK(2,1,0) \
    )
#  define _DAI_ALWAYS_INLINE _Pragma("FUNC_ALWAYS_INLINE;")
#elif _DAI_IAR_VERSION_CHECK(8,0,0)
#  define _DAI_ALWAYS_INLINE _Pragma("inline=forced")
#else
#  define _DAI_ALWAYS_INLINE _DAI_INLINE
#endif

#if defined(_DAI_NEVER_INLINE)
#  undef _DAI_NEVER_INLINE
#endif
#if \
  _DAI_HAS_ATTRIBUTE(noinline) || \
  _DAI_GCC_VERSION_CHECK(4,0,0) || \
  _DAI_INTEL_VERSION_CHECK(13,0,0) || \
  _DAI_SUNPRO_VERSION_CHECK(5,11,0) || \
  _DAI_ARM_VERSION_CHECK(4,1,0) || \
  _DAI_IBM_VERSION_CHECK(10,1,0) || \
  _DAI_TI_VERSION_CHECK(15,12,0) || \
  (_DAI_TI_ARMCL_VERSION_CHECK(4,8,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_ARMCL_VERSION_CHECK(5,2,0) || \
  (_DAI_TI_CL2000_VERSION_CHECK(6,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL2000_VERSION_CHECK(6,4,0) || \
  (_DAI_TI_CL430_VERSION_CHECK(4,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL430_VERSION_CHECK(4,3,0) || \
  (_DAI_TI_CL6X_VERSION_CHECK(7,2,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  _DAI_TI_CL6X_VERSION_CHECK(7,5,0) || \
  _DAI_TI_CL7X_VERSION_CHECK(1,2,0) || \
  _DAI_TI_CLPRU_VERSION_CHECK(2,1,0) || \
  _DAI_MCST_LCC_VERSION_CHECK(1,25,10) || \
  _DAI_IAR_VERSION_CHECK(8,10,0)
#  define _DAI_NEVER_INLINE __attribute__((__noinline__))
#elif \
  _DAI_MSVC_VERSION_CHECK(13,10,0) || \
  _DAI_INTEL_CL_VERSION_CHECK(2021,1,0)
#  define _DAI_NEVER_INLINE __declspec(noinline)
#elif _DAI_PGI_VERSION_CHECK(10,2,0)
#  define _DAI_NEVER_INLINE _Pragma("noinline")
#elif _DAI_TI_CL6X_VERSION_CHECK(6,0,0) && defined(__cplusplus)
#  define _DAI_NEVER_INLINE _Pragma("FUNC_CANNOT_INLINE;")
#elif _DAI_IAR_VERSION_CHECK(8,0,0)
#  define _DAI_NEVER_INLINE _Pragma("inline=never")
#elif _DAI_COMPCERT_VERSION_CHECK(3,2,0)
#  define _DAI_NEVER_INLINE __attribute((noinline))
#elif _DAI_PELLES_VERSION_CHECK(9,0,0)
#  define _DAI_NEVER_INLINE __declspec(noinline)
#else
#  define _DAI_NEVER_INLINE
#endif

#if defined(_DAI_PRIVATE)
#  undef _DAI_PRIVATE
#endif
#if defined(_DAI_PUBLIC)
#  undef _DAI_PUBLIC
#endif
#if defined(_DAI_IMPORT)
#  undef _DAI_IMPORT
#endif
#if defined(_WIN32) || defined(__CYGWIN__)
#  define _DAI_PRIVATE
#  define _DAI_PUBLIC   __declspec(dllexport)
#  define _DAI_IMPORT   __declspec(dllimport)
#else
#  if \
    _DAI_HAS_ATTRIBUTE(visibility) || \
    _DAI_GCC_VERSION_CHECK(3,3,0) || \
    _DAI_SUNPRO_VERSION_CHECK(5,11,0) || \
    _DAI_INTEL_VERSION_CHECK(13,0,0) || \
    _DAI_ARM_VERSION_CHECK(4,1,0) || \
    _DAI_IBM_VERSION_CHECK(13,1,0) || \
    ( \
      defined(__TI_EABI__) && \
      ( \
        (_DAI_TI_CL6X_VERSION_CHECK(7,2,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
        _DAI_TI_CL6X_VERSION_CHECK(7,5,0) \
      ) \
    ) || \
    _DAI_MCST_LCC_VERSION_CHECK(1,25,10)
#    define _DAI_PRIVATE __attribute__((__visibility__("hidden")))
#    define _DAI_PUBLIC  __attribute__((__visibility__("default")))
#  else
#    define _DAI_PRIVATE
#    define _DAI_PUBLIC
#  endif
#  define _DAI_IMPORT    extern
#endif

#if defined(_DAI_NO_THROW)
#  undef _DAI_NO_THROW
#endif
#if \
  _DAI_HAS_ATTRIBUTE(nothrow) || \
  _DAI_GCC_VERSION_CHECK(3,3,0) || \
  _DAI_INTEL_VERSION_CHECK(13,0,0) || \
  _DAI_MCST_LCC_VERSION_CHECK(1,25,10)
#  define _DAI_NO_THROW __attribute__((__nothrow__))
#elif \
  _DAI_MSVC_VERSION_CHECK(13,1,0) || \
  _DAI_INTEL_CL_VERSION_CHECK(2021,1,0) || \
  _DAI_ARM_VERSION_CHECK(4,1,0)
#  define _DAI_NO_THROW __declspec(nothrow)
#else
#  define _DAI_NO_THROW
#endif

#if defined(_DAI_FALL_THROUGH)
# undef _DAI_FALL_THROUGH
#endif
#if \
  _DAI_HAS_ATTRIBUTE(fallthrough) || \
  _DAI_GCC_VERSION_CHECK(7,0,0) || \
  _DAI_MCST_LCC_VERSION_CHECK(1,25,10)
#  define _DAI_FALL_THROUGH __attribute__((__fallthrough__))
#elif _DAI_HAS_CPP_ATTRIBUTE_NS(clang,fallthrough)
#  define _DAI_FALL_THROUGH _DAI_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_([[clang::fallthrough]])
#elif _DAI_HAS_CPP_ATTRIBUTE(fallthrough)
#  define _DAI_FALL_THROUGH _DAI_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_([[fallthrough]])
#elif defined(__fallthrough) /* SAL */
#  define _DAI_FALL_THROUGH __fallthrough
#else
#  define _DAI_FALL_THROUGH
#endif

#if defined(_DAI_RETURNS_NON_NULL)
#  undef _DAI_RETURNS_NON_NULL
#endif
#if \
  _DAI_HAS_ATTRIBUTE(returns_nonnull) || \
  _DAI_GCC_VERSION_CHECK(4,9,0) || \
  _DAI_MCST_LCC_VERSION_CHECK(1,25,10)
#  define _DAI_RETURNS_NON_NULL __attribute__((__returns_nonnull__))
#elif defined(_Ret_notnull_) /* SAL */
#  define _DAI_RETURNS_NON_NULL _Ret_notnull_
#else
#  define _DAI_RETURNS_NON_NULL
#endif

#if defined(_DAI_ARRAY_PARAM)
#  undef _DAI_ARRAY_PARAM
#endif
#if \
  defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L) && \
  !defined(__STDC_NO_VLA__) && \
  !defined(__cplusplus) && \
  !defined(_DAI_PGI_VERSION) && \
  !defined(_DAI_TINYC_VERSION)
#  define _DAI_ARRAY_PARAM(name) (name)
#else
#  define _DAI_ARRAY_PARAM(name)
#endif

#if defined(_DAI_IS_CONSTANT)
#  undef _DAI_IS_CONSTANT
#endif
#if defined(_DAI_REQUIRE_CONSTEXPR)
#  undef _DAI_REQUIRE_CONSTEXPR
#endif
/* _DAI_IS_CONSTEXPR_ is for
   HEDLEY INTERNAL USE ONLY.  API subject to change without notice. */
#if defined(_DAI_IS_CONSTEXPR_)
#  undef _DAI_IS_CONSTEXPR_
#endif
#if \
  _DAI_HAS_BUILTIN(__builtin_constant_p) || \
  _DAI_GCC_VERSION_CHECK(3,4,0) || \
  _DAI_INTEL_VERSION_CHECK(13,0,0) || \
  _DAI_TINYC_VERSION_CHECK(0,9,19) || \
  _DAI_ARM_VERSION_CHECK(4,1,0) || \
  _DAI_IBM_VERSION_CHECK(13,1,0) || \
  _DAI_TI_CL6X_VERSION_CHECK(6,1,0) || \
  (_DAI_SUNPRO_VERSION_CHECK(5,10,0) && !defined(__cplusplus)) || \
  _DAI_CRAY_VERSION_CHECK(8,1,0) || \
  _DAI_MCST_LCC_VERSION_CHECK(1,25,10)
#  define _DAI_IS_CONSTANT(expr) __builtin_constant_p(expr)
#endif
#if !defined(__cplusplus)
#  if \
       _DAI_HAS_BUILTIN(__builtin_types_compatible_p) || \
       _DAI_GCC_VERSION_CHECK(3,4,0) || \
       _DAI_INTEL_VERSION_CHECK(13,0,0) || \
       _DAI_IBM_VERSION_CHECK(13,1,0) || \
       _DAI_CRAY_VERSION_CHECK(8,1,0) || \
       _DAI_ARM_VERSION_CHECK(5,4,0) || \
       _DAI_TINYC_VERSION_CHECK(0,9,24)
#    if defined(__INTPTR_TYPE__)
#      define _DAI_IS_CONSTEXPR_(expr) __builtin_types_compatible_p(__typeof__((1 ? (void*) ((__INTPTR_TYPE__) ((expr) * 0)) : (int*) 0)), int*)
#    else
#      include <stdint.h>
#      define _DAI_IS_CONSTEXPR_(expr) __builtin_types_compatible_p(__typeof__((1 ? (void*) ((intptr_t) ((expr) * 0)) : (int*) 0)), int*)
#    endif
#  elif \
       ( \
          defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L) && \
          !defined(_DAI_SUNPRO_VERSION) && \
          !defined(_DAI_PGI_VERSION) && \
          !defined(_DAI_IAR_VERSION)) || \
       (_DAI_HAS_EXTENSION(c_generic_selections) && !defined(_DAI_IAR_VERSION)) || \
       _DAI_GCC_VERSION_CHECK(4,9,0) || \
       _DAI_INTEL_VERSION_CHECK(17,0,0) || \
       _DAI_IBM_VERSION_CHECK(12,1,0) || \
       _DAI_ARM_VERSION_CHECK(5,3,0)
#    if defined(__INTPTR_TYPE__)
#      define _DAI_IS_CONSTEXPR_(expr) _Generic((1 ? (void*) ((__INTPTR_TYPE__) ((expr) * 0)) : (int*) 0), int*: 1, void*: 0)
#    else
#      include <stdint.h>
#      define _DAI_IS_CONSTEXPR_(expr) _Generic((1 ? (void*) ((intptr_t) * 0) : (int*) 0), int*: 1, void*: 0)
#    endif
#  elif \
       defined(_DAI_GCC_VERSION) || \
       defined(_DAI_INTEL_VERSION) || \
       defined(_DAI_TINYC_VERSION) || \
       defined(_DAI_TI_ARMCL_VERSION) || \
       _DAI_TI_CL430_VERSION_CHECK(18,12,0) || \
       defined(_DAI_TI_CL2000_VERSION) || \
       defined(_DAI_TI_CL6X_VERSION) || \
       defined(_DAI_TI_CL7X_VERSION) || \
       defined(_DAI_TI_CLPRU_VERSION) || \
       defined(__clang__)
#    define _DAI_IS_CONSTEXPR_(expr) ( \
         sizeof(void) != \
         sizeof(*( \
           1 ? \
             ((void*) ((expr) * 0L) ) : \
             ((struct { char v[sizeof(void) * 2]; } *) 1) \
           ) \
         ) \
       )
#  endif
#endif
#if defined(_DAI_IS_CONSTEXPR_)
#  if !defined(_DAI_IS_CONSTANT)
#    define _DAI_IS_CONSTANT(expr) _DAI_IS_CONSTEXPR_(expr)
#  endif
#  define _DAI_REQUIRE_CONSTEXPR(expr) (_DAI_IS_CONSTEXPR_(expr) ? (expr) : (-1))
#else
#  if !defined(_DAI_IS_CONSTANT)
#    define _DAI_IS_CONSTANT(expr) (0)
#  endif
#  define _DAI_REQUIRE_CONSTEXPR(expr) (expr)
#endif

#if defined(_DAI_BEGIN_C_DECLS)
#  undef _DAI_BEGIN_C_DECLS
#endif
#if defined(_DAI_END_C_DECLS)
#  undef _DAI_END_C_DECLS
#endif
#if defined(_DAI_C_DECL)
#  undef _DAI_C_DECL
#endif
#if defined(__cplusplus)
#  define _DAI_BEGIN_C_DECLS extern "C" {
#  define _DAI_END_C_DECLS }
#  define _DAI_C_DECL extern "C"
#else
#  define _DAI_BEGIN_C_DECLS
#  define _DAI_END_C_DECLS
#  define _DAI_C_DECL
#endif

#if defined(_DAI_STATIC_ASSERT)
#  undef _DAI_STATIC_ASSERT
#endif
#if \
  !defined(__cplusplus) && ( \
      (defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)) || \
      (_DAI_HAS_FEATURE(c_static_assert) && !defined(_DAI_INTEL_CL_VERSION)) || \
      _DAI_GCC_VERSION_CHECK(6,0,0) || \
      _DAI_INTEL_VERSION_CHECK(13,0,0) || \
      defined(_Static_assert) \
    )
#  define _DAI_STATIC_ASSERT(expr, message) _Static_assert(expr, message)
#elif \
  (defined(__cplusplus) && (__cplusplus >= 201103L)) || \
  _DAI_MSVC_VERSION_CHECK(16,0,0) || \
  _DAI_INTEL_CL_VERSION_CHECK(2021,1,0)
#  define _DAI_STATIC_ASSERT(expr, message) _DAI_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_(static_assert(expr, message))
#else
#  define _DAI_STATIC_ASSERT(expr, message)
#endif

#if defined(_DAI_NULL)
#  undef _DAI_NULL
#endif
#if defined(__cplusplus)
#  if __cplusplus >= 201103L
#    define _DAI_NULL _DAI_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_(nullptr)
#  elif defined(NULL)
#    define _DAI_NULL NULL
#  else
#    define _DAI_NULL _DAI_STATIC_CAST(void*, 0)
#  endif
#elif defined(NULL)
#  define _DAI_NULL NULL
#else
#  define _DAI_NULL ((void*) 0)
#endif

#if defined(_DAI_MESSAGE)
#  undef _DAI_MESSAGE
#endif
#if _DAI_HAS_WARNING("-Wunknown-pragmas")
#  define _DAI_MESSAGE(msg) \
  _DAI_DIAGNOSTIC_PUSH \
  _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS \
  _DAI_PRAGMA(message msg) \
  _DAI_DIAGNOSTIC_POP
#elif \
  _DAI_GCC_VERSION_CHECK(4,4,0) || \
  _DAI_INTEL_VERSION_CHECK(13,0,0)
#  define _DAI_MESSAGE(msg) _DAI_PRAGMA(message msg)
#elif _DAI_CRAY_VERSION_CHECK(5,0,0)
#  define _DAI_MESSAGE(msg) _DAI_PRAGMA(_CRI message msg)
#elif _DAI_IAR_VERSION_CHECK(8,0,0)
#  define _DAI_MESSAGE(msg) _DAI_PRAGMA(message(msg))
#elif _DAI_PELLES_VERSION_CHECK(2,0,0)
#  define _DAI_MESSAGE(msg) _DAI_PRAGMA(message(msg))
#else
#  define _DAI_MESSAGE(msg)
#endif

#if defined(_DAI_WARNING)
#  undef _DAI_WARNING
#endif
#if _DAI_HAS_WARNING("-Wunknown-pragmas")
#  define _DAI_WARNING(msg) \
  _DAI_DIAGNOSTIC_PUSH \
  _DAI_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS \
  _DAI_PRAGMA(clang warning msg) \
  _DAI_DIAGNOSTIC_POP
#elif \
  _DAI_GCC_VERSION_CHECK(4,8,0) || \
  _DAI_PGI_VERSION_CHECK(18,4,0) || \
  _DAI_INTEL_VERSION_CHECK(13,0,0)
#  define _DAI_WARNING(msg) _DAI_PRAGMA(GCC warning msg)
#elif \
  _DAI_MSVC_VERSION_CHECK(15,0,0) || \
  _DAI_INTEL_CL_VERSION_CHECK(2021,1,0)
#  define _DAI_WARNING(msg) _DAI_PRAGMA(message(msg))
#else
#  define _DAI_WARNING(msg) _DAI_MESSAGE(msg)
#endif

#if defined(_DAI_REQUIRE)
#  undef _DAI_REQUIRE
#endif
#if defined(_DAI_REQUIRE_MSG)
#  undef _DAI_REQUIRE_MSG
#endif
#if _DAI_HAS_ATTRIBUTE(diagnose_if)
#  if _DAI_HAS_WARNING("-Wgcc-compat")
#    define _DAI_REQUIRE(expr) \
       _DAI_DIAGNOSTIC_PUSH \
       _Pragma("clang diagnostic ignored \"-Wgcc-compat\"") \
       __attribute__((diagnose_if(!(expr), #expr, "error"))) \
       _DAI_DIAGNOSTIC_POP
#    define _DAI_REQUIRE_MSG(expr,msg) \
       _DAI_DIAGNOSTIC_PUSH \
       _Pragma("clang diagnostic ignored \"-Wgcc-compat\"") \
       __attribute__((diagnose_if(!(expr), msg, "error"))) \
       _DAI_DIAGNOSTIC_POP
#  else
#    define _DAI_REQUIRE(expr) __attribute__((diagnose_if(!(expr), #expr, "error")))
#    define _DAI_REQUIRE_MSG(expr,msg) __attribute__((diagnose_if(!(expr), msg, "error")))
#  endif
#else
#  define _DAI_REQUIRE(expr)
#  define _DAI_REQUIRE_MSG(expr,msg)
#endif

#if defined(_DAI_FLAGS)
#  undef _DAI_FLAGS
#endif
#if _DAI_HAS_ATTRIBUTE(flag_enum) && (!defined(__cplusplus) || _DAI_HAS_WARNING("-Wbitfield-enum-conversion"))
#  define _DAI_FLAGS __attribute__((__flag_enum__))
#else
#  define _DAI_FLAGS
#endif

#if defined(_DAI_FLAGS_CAST)
#  undef _DAI_FLAGS_CAST
#endif
#if _DAI_INTEL_VERSION_CHECK(19,0,0)
#  define _DAI_FLAGS_CAST(T, expr) (__extension__ ({ \
  _DAI_DIAGNOSTIC_PUSH \
      _Pragma("warning(disable:188)") \
      ((T) (expr)); \
      _DAI_DIAGNOSTIC_POP \
    }))
#else
#  define _DAI_FLAGS_CAST(T, expr) _DAI_STATIC_CAST(T, expr)
#endif

#if defined(_DAI_EMPTY_BASES)
#  undef _DAI_EMPTY_BASES
#endif
#if \
  (_DAI_MSVC_VERSION_CHECK(19,0,23918) && !_DAI_MSVC_VERSION_CHECK(20,0,0)) || \
  _DAI_INTEL_CL_VERSION_CHECK(2021,1,0)
#  define _DAI_EMPTY_BASES __declspec(empty_bases)
#else
#  define _DAI_EMPTY_BASES
#endif

/* Remaining macros are deprecated. */

#if defined(_DAI_GCC_NOT_CLANG_VERSION_CHECK)
#  undef _DAI_GCC_NOT_CLANG_VERSION_CHECK
#endif
#if defined(__clang__)
#  define _DAI_GCC_NOT_CLANG_VERSION_CHECK(major,minor,patch) (0)
#else
#  define _DAI_GCC_NOT_CLANG_VERSION_CHECK(major,minor,patch) _DAI_GCC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(_DAI_CLANG_HAS_ATTRIBUTE)
#  undef _DAI_CLANG_HAS_ATTRIBUTE
#endif
#define _DAI_CLANG_HAS_ATTRIBUTE(attribute) _DAI_HAS_ATTRIBUTE(attribute)

#if defined(_DAI_CLANG_HAS_CPP_ATTRIBUTE)
#  undef _DAI_CLANG_HAS_CPP_ATTRIBUTE
#endif
#define _DAI_CLANG_HAS_CPP_ATTRIBUTE(attribute) _DAI_HAS_CPP_ATTRIBUTE(attribute)

#if defined(_DAI_CLANG_HAS_BUILTIN)
#  undef _DAI_CLANG_HAS_BUILTIN
#endif
#define _DAI_CLANG_HAS_BUILTIN(builtin) _DAI_HAS_BUILTIN(builtin)

#if defined(_DAI_CLANG_HAS_FEATURE)
#  undef _DAI_CLANG_HAS_FEATURE
#endif
#define _DAI_CLANG_HAS_FEATURE(feature) _DAI_HAS_FEATURE(feature)

#if defined(_DAI_CLANG_HAS_EXTENSION)
#  undef _DAI_CLANG_HAS_EXTENSION
#endif
#define _DAI_CLANG_HAS_EXTENSION(extension) _DAI_HAS_EXTENSION(extension)

#if defined(_DAI_CLANG_HAS_DECLSPEC_DECLSPEC_ATTRIBUTE)
#  undef _DAI_CLANG_HAS_DECLSPEC_DECLSPEC_ATTRIBUTE
#endif
#define _DAI_CLANG_HAS_DECLSPEC_ATTRIBUTE(attribute) _DAI_HAS_DECLSPEC_ATTRIBUTE(attribute)

#if defined(_DAI_CLANG_HAS_WARNING)
#  undef _DAI_CLANG_HAS_WARNING
#endif
#define _DAI_CLANG_HAS_WARNING(warning) _DAI_HAS_WARNING(warning)

#endif /* !defined(_DAI_HEDLEY_VERSION) || (_DAI_HEDLEY_VERSION < X) */
