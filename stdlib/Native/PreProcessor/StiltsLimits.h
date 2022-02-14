#ifndef __STILTS_STDLIB_LIMITS
#define __STILTS_STDLIB_LIMITS

/* Assumes two's compliment, and CHAR_BIT = 8, as asserted in the confugure file. */
/* Also assumes that uintmax_t is indeed the largest unsigned int type (which may not actually
 * always be correct). Works up to */

#define __STILTS_LIMITS_LEFTSHIFT(num, shf)                                                       \
    ((shf > 0 ? (uintmax_t)2 : 1) * (shf > 1 ? (uintmax_t)2 : 1) * (shf > 2 ? (uintmax_t)2 : 1) * \
     (shf > 3 ? (uintmax_t)2 : 1) * (shf > 4 ? (uintmax_t)2 : 1) * (shf > 5 ? (uintmax_t)2 : 1) * \
     (shf > 6 ? (uintmax_t)2 : 1) * (shf > 7 ? (uintmax_t)2 : 1) * (shf > 8 ? (uintmax_t)2 : 1) * \
     (shf > 9 ? (uintmax_t)2 : 1) * (shf > 10 ? (uintmax_t)2 : 1) *                               \
     (shf > 11 ? (uintmax_t)2 : 1) * (shf > 12 ? (uintmax_t)2 : 1) *                              \
     (shf > 13 ? (uintmax_t)2 : 1) * (shf > 14 ? (uintmax_t)2 : 1) *                              \
     (shf > 15 ? (uintmax_t)2 : 1) * (shf > 16 ? (uintmax_t)2 : 1) *                              \
     (shf > 17 ? (uintmax_t)2 : 1) * (shf > 18 ? (uintmax_t)2 : 1) *                              \
     (shf > 19 ? (uintmax_t)2 : 1) * (shf > 20 ? (uintmax_t)2 : 1) *                              \
     (shf > 21 ? (uintmax_t)2 : 1) * (shf > 22 ? (uintmax_t)2 : 1) *                              \
     (shf > 23 ? (uintmax_t)2 : 1) * (shf > 24 ? (uintmax_t)2 : 1) *                              \
     (shf > 25 ? (uintmax_t)2 : 1) * (shf > 26 ? (uintmax_t)2 : 1) *                              \
     (shf > 27 ? (uintmax_t)2 : 1) * (shf > 28 ? (uintmax_t)2 : 1) *                              \
     (shf > 29 ? (uintmax_t)2 : 1) * (shf > 30 ? (uintmax_t)2 : 1) *                              \
     (shf > 31 ? (uintmax_t)2 : 1) * (shf > 32 ? (uintmax_t)2 : 1) *                              \
     (shf > 33 ? (uintmax_t)2 : 1) * (shf > 34 ? (uintmax_t)2 : 1) *                              \
     (shf > 35 ? (uintmax_t)2 : 1) * (shf > 36 ? (uintmax_t)2 : 1) *                              \
     (shf > 37 ? (uintmax_t)2 : 1) * (shf > 38 ? (uintmax_t)2 : 1) *                              \
     (shf > 39 ? (uintmax_t)2 : 1) * (shf > 40 ? (uintmax_t)2 : 1) *                              \
     (shf > 41 ? (uintmax_t)2 : 1) * (shf > 42 ? (uintmax_t)2 : 1) *                              \
     (shf > 43 ? (uintmax_t)2 : 1) * (shf > 44 ? (uintmax_t)2 : 1) *                              \
     (shf > 45 ? (uintmax_t)2 : 1) * (shf > 46 ? (uintmax_t)2 : 1) *                              \
     (shf > 47 ? (uintmax_t)2 : 1) * (shf > 48 ? (uintmax_t)2 : 1) *                              \
     (shf > 49 ? (uintmax_t)2 : 1) * (shf > 50 ? (uintmax_t)2 : 1) *                              \
     (shf > 51 ? (uintmax_t)2 : 1) * (shf > 52 ? (uintmax_t)2 : 1) *                              \
     (shf > 53 ? (uintmax_t)2 : 1) * (shf > 54 ? (uintmax_t)2 : 1) *                              \
     (shf > 55 ? (uintmax_t)2 : 1) * (shf > 56 ? (uintmax_t)2 : 1) *                              \
     (shf > 57 ? (uintmax_t)2 : 1) * (shf > 58 ? (uintmax_t)2 : 1) *                              \
     (shf > 59 ? (uintmax_t)2 : 1) * (shf > 60 ? (uintmax_t)2 : 1) *                              \
     (shf > 61 ? (uintmax_t)2 : 1) * (shf > 62 ? (uintmax_t)2 : 1) *                              \
     (shf > 63 ? (uintmax_t)2 : 1) * (shf > 64 ? (uintmax_t)2 : 1) *                              \
     (shf > 65 ? (uintmax_t)2 : 1) * (shf > 66 ? (uintmax_t)2 : 1) *                              \
     (shf > 67 ? (uintmax_t)2 : 1) * (shf > 68 ? (uintmax_t)2 : 1) *                              \
     (shf > 69 ? (uintmax_t)2 : 1) * (shf > 70 ? (uintmax_t)2 : 1) *                              \
     (shf > 71 ? (uintmax_t)2 : 1) * (shf > 72 ? (uintmax_t)2 : 1) *                              \
     (shf > 73 ? (uintmax_t)2 : 1) * (shf > 74 ? (uintmax_t)2 : 1) *                              \
     (shf > 75 ? (uintmax_t)2 : 1) * (shf > 76 ? (uintmax_t)2 : 1) *                              \
     (shf > 77 ? (uintmax_t)2 : 1) * (shf > 78 ? (uintmax_t)2 : 1) *                              \
     (shf > 79 ? (uintmax_t)2 : 1) * (shf > 80 ? (uintmax_t)2 : 1) *                              \
     (shf > 81 ? (uintmax_t)2 : 1) * (shf > 82 ? (uintmax_t)2 : 1) *                              \
     (shf > 83 ? (uintmax_t)2 : 1) * (shf > 84 ? (uintmax_t)2 : 1) *                              \
     (shf > 85 ? (uintmax_t)2 : 1) * (shf > 86 ? (uintmax_t)2 : 1) *                              \
     (shf > 87 ? (uintmax_t)2 : 1) * (shf > 88 ? (uintmax_t)2 : 1) *                              \
     (shf > 89 ? (uintmax_t)2 : 1) * (shf > 90 ? (uintmax_t)2 : 1) *                              \
     (shf > 91 ? (uintmax_t)2 : 1) * (shf > 92 ? (uintmax_t)2 : 1) *                              \
     (shf > 93 ? (uintmax_t)2 : 1) * (shf > 94 ? (uintmax_t)2 : 1) *                              \
     (shf > 95 ? (uintmax_t)2 : 1) * (shf > 96 ? (uintmax_t)2 : 1) *                              \
     (shf > 97 ? (uintmax_t)2 : 1) * (shf > 98 ? (uintmax_t)2 : 1) *                              \
     (shf > 99 ? (uintmax_t)2 : 1) * (shf > 100 ? (uintmax_t)2 : 1) *                             \
     (shf > 101 ? (uintmax_t)2 : 1) * (shf > 102 ? (uintmax_t)2 : 1) *                            \
     (shf > 103 ? (uintmax_t)2 : 1) * (shf > 104 ? (uintmax_t)2 : 1) *                            \
     (shf > 105 ? (uintmax_t)2 : 1) * (shf > 106 ? (uintmax_t)2 : 1) *                            \
     (shf > 107 ? (uintmax_t)2 : 1) * (shf > 108 ? (uintmax_t)2 : 1) *                            \
     (shf > 109 ? (uintmax_t)2 : 1) * (shf > 110 ? (uintmax_t)2 : 1) *                            \
     (shf > 111 ? (uintmax_t)2 : 1) * (shf > 112 ? (uintmax_t)2 : 1) *                            \
     (shf > 113 ? (uintmax_t)2 : 1) * (shf > 114 ? (uintmax_t)2 : 1) *                            \
     (shf > 115 ? (uintmax_t)2 : 1) * (shf > 116 ? (uintmax_t)2 : 1) *                            \
     (shf > 117 ? (uintmax_t)2 : 1) * (shf > 118 ? (uintmax_t)2 : 1) *                            \
     (shf > 119 ? (uintmax_t)2 : 1) * (shf > 120 ? (uintmax_t)2 : 1) *                            \
     (shf > 121 ? (uintmax_t)2 : 1) * (shf > 122 ? (uintmax_t)2 : 1) *                            \
     (shf > 123 ? (uintmax_t)2 : 1) * (shf > 124 ? (uintmax_t)2 : 1) *                            \
     (shf > 125 ? (uintmax_t)2 : 1) * (shf > 126 ? (uintmax_t)2 : 1) *                            \
     (shf > 127 ? (uintmax_t)2 : 1) * (shf > 128 ? (uintmax_t)2 : 1) *                            \
     (shf > 129 ? (uintmax_t)2 : 1) * (shf > 130 ? (uintmax_t)2 : 1) *                            \
     (shf > 131 ? (uintmax_t)2 : 1) * (shf > 132 ? (uintmax_t)2 : 1) *                            \
     (shf > 133 ? (uintmax_t)2 : 1) * (shf > 134 ? (uintmax_t)2 : 1) *                            \
     (shf > 135 ? (uintmax_t)2 : 1) * (shf > 136 ? (uintmax_t)2 : 1) *                            \
     (shf > 137 ? (uintmax_t)2 : 1) * (shf > 138 ? (uintmax_t)2 : 1) *                            \
     (shf > 139 ? (uintmax_t)2 : 1) * (shf > 140 ? (uintmax_t)2 : 1) *                            \
     (shf > 141 ? (uintmax_t)2 : 1) * (shf > 142 ? (uintmax_t)2 : 1) *                            \
     (shf > 143 ? (uintmax_t)2 : 1) * (shf > 144 ? (uintmax_t)2 : 1) *                            \
     (shf > 145 ? (uintmax_t)2 : 1) * (shf > 146 ? (uintmax_t)2 : 1) *                            \
     (shf > 147 ? (uintmax_t)2 : 1) * (shf > 148 ? (uintmax_t)2 : 1) *                            \
     (shf > 149 ? (uintmax_t)2 : 1) * (shf > 150 ? (uintmax_t)2 : 1) *                            \
     (shf > 151 ? (uintmax_t)2 : 1) * (shf > 152 ? (uintmax_t)2 : 1) *                            \
     (shf > 153 ? (uintmax_t)2 : 1) * (shf > 154 ? (uintmax_t)2 : 1) *                            \
     (shf > 155 ? (uintmax_t)2 : 1) * (shf > 156 ? (uintmax_t)2 : 1) *                            \
     (shf > 157 ? (uintmax_t)2 : 1) * (shf > 158 ? (uintmax_t)2 : 1) *                            \
     (shf > 159 ? (uintmax_t)2 : 1) * (shf > 160 ? (uintmax_t)2 : 1) *                            \
     (shf > 161 ? (uintmax_t)2 : 1) * (shf > 162 ? (uintmax_t)2 : 1) *                            \
     (shf > 163 ? (uintmax_t)2 : 1) * (shf > 164 ? (uintmax_t)2 : 1) *                            \
     (shf > 165 ? (uintmax_t)2 : 1) * (shf > 166 ? (uintmax_t)2 : 1) *                            \
     (shf > 167 ? (uintmax_t)2 : 1) * (shf > 168 ? (uintmax_t)2 : 1) *                            \
     (shf > 169 ? (uintmax_t)2 : 1) * (shf > 170 ? (uintmax_t)2 : 1) *                            \
     (shf > 171 ? (uintmax_t)2 : 1) * (shf > 172 ? (uintmax_t)2 : 1) *                            \
     (shf > 173 ? (uintmax_t)2 : 1) * (shf > 174 ? (uintmax_t)2 : 1) *                            \
     (shf > 175 ? (uintmax_t)2 : 1) * (shf > 176 ? (uintmax_t)2 : 1) *                            \
     (shf > 177 ? (uintmax_t)2 : 1) * (shf > 178 ? (uintmax_t)2 : 1) *                            \
     (shf > 179 ? (uintmax_t)2 : 1) * (shf > 180 ? (uintmax_t)2 : 1) *                            \
     (shf > 181 ? (uintmax_t)2 : 1) * (shf > 182 ? (uintmax_t)2 : 1) *                            \
     (shf > 183 ? (uintmax_t)2 : 1) * (shf > 184 ? (uintmax_t)2 : 1) *                            \
     (shf > 185 ? (uintmax_t)2 : 1) * (shf > 186 ? (uintmax_t)2 : 1) *                            \
     (shf > 187 ? (uintmax_t)2 : 1) * (shf > 188 ? (uintmax_t)2 : 1) *                            \
     (shf > 189 ? (uintmax_t)2 : 1) * (shf > 190 ? (uintmax_t)2 : 1) *                            \
     (shf > 191 ? (uintmax_t)2 : 1) * (shf > 192 ? (uintmax_t)2 : 1) *                            \
     (shf > 193 ? (uintmax_t)2 : 1) * (shf > 194 ? (uintmax_t)2 : 1) *                            \
     (shf > 195 ? (uintmax_t)2 : 1) * (shf > 196 ? (uintmax_t)2 : 1) *                            \
     (shf > 197 ? (uintmax_t)2 : 1) * (shf > 198 ? (uintmax_t)2 : 1) *                            \
     (shf > 199 ? (uintmax_t)2 : 1) * (shf > 200 ? (uintmax_t)2 : 1) *                            \
     (shf > 201 ? (uintmax_t)2 : 1) * (shf > 202 ? (uintmax_t)2 : 1) *                            \
     (shf > 203 ? (uintmax_t)2 : 1) * (shf > 204 ? (uintmax_t)2 : 1) *                            \
     (shf > 205 ? (uintmax_t)2 : 1) * (shf > 206 ? (uintmax_t)2 : 1) *                            \
     (shf > 207 ? (uintmax_t)2 : 1) * (shf > 208 ? (uintmax_t)2 : 1) *                            \
     (shf > 209 ? (uintmax_t)2 : 1) * (shf > 210 ? (uintmax_t)2 : 1) *                            \
     (shf > 211 ? (uintmax_t)2 : 1) * (shf > 212 ? (uintmax_t)2 : 1) *                            \
     (shf > 213 ? (uintmax_t)2 : 1) * (shf > 214 ? (uintmax_t)2 : 1) *                            \
     (shf > 215 ? (uintmax_t)2 : 1) * (shf > 216 ? (uintmax_t)2 : 1) *                            \
     (shf > 217 ? (uintmax_t)2 : 1) * (shf > 218 ? (uintmax_t)2 : 1) *                            \
     (shf > 219 ? (uintmax_t)2 : 1) * (shf > 220 ? (uintmax_t)2 : 1) *                            \
     (shf > 221 ? (uintmax_t)2 : 1) * (shf > 222 ? (uintmax_t)2 : 1) *                            \
     (shf > 223 ? (uintmax_t)2 : 1) * (shf > 224 ? (uintmax_t)2 : 1) *                            \
     (shf > 225 ? (uintmax_t)2 : 1) * (shf > 226 ? (uintmax_t)2 : 1) *                            \
     (shf > 227 ? (uintmax_t)2 : 1) * (shf > 228 ? (uintmax_t)2 : 1) *                            \
     (shf > 229 ? (uintmax_t)2 : 1) * (shf > 230 ? (uintmax_t)2 : 1) *                            \
     (shf > 231 ? (uintmax_t)2 : 1) * (shf > 232 ? (uintmax_t)2 : 1) *                            \
     (shf > 233 ? (uintmax_t)2 : 1) * (shf > 234 ? (uintmax_t)2 : 1) *                            \
     (shf > 235 ? (uintmax_t)2 : 1) * (shf > 236 ? (uintmax_t)2 : 1) *                            \
     (shf > 237 ? (uintmax_t)2 : 1) * (shf > 238 ? (uintmax_t)2 : 1) *                            \
     (shf > 239 ? (uintmax_t)2 : 1) * (shf > 240 ? (uintmax_t)2 : 1) *                            \
     (shf > 241 ? (uintmax_t)2 : 1) * (shf > 242 ? (uintmax_t)2 : 1) *                            \
     (shf > 243 ? (uintmax_t)2 : 1) * (shf > 244 ? (uintmax_t)2 : 1) *                            \
     (shf > 245 ? (uintmax_t)2 : 1) * (shf > 246 ? (uintmax_t)2 : 1) *                            \
     (shf > 247 ? (uintmax_t)2 : 1) * (shf > 248 ? (uintmax_t)2 : 1) *                            \
     (shf > 249 ? (uintmax_t)2 : 1) * (shf > 250 ? (uintmax_t)2 : 1) *                            \
     (shf > 251 ? (uintmax_t)2 : 1) * (shf > 252 ? (uintmax_t)2 : 1) *                            \
     (shf > 253 ? (uintmax_t)2 : 1) * (shf > 254 ? (uintmax_t)2 : 1) *                            \
     (shf > 255 ? (uintmax_t)2 : 1) * (num))

#define __STILTS_IS_TYPE_SIGNED(t) (((t)(-1)) < ((t)0))
#define __STILTS_IS_TYPE_FLOATING(t) \
    _Generic((t)0, float : 1, double : 1, long double : 1, default : 0)

#define __STILTS_MAX_OF_UNSIGNED_INTEGER_TYPE(t)                           \
    ((t)(__STILTS_LIMITS_LEFTSHIFT((uintmax_t)1, sizeof(t) * 8 - 1) - 1) | \
     __STILTS_LIMITS_LEFTSHIFT((uintmax_t)15, sizeof(t) * 8 - 4))
#define __STILTS_MAX_OF_SIGNED_INTEGER_TYPE(t)                             \
    ((t)(__STILTS_LIMITS_LEFTSHIFT((uintmax_t)1, sizeof(t) * 8 - 1) - 1) | \
     __STILTS_LIMITS_LEFTSHIFT((uintmax_t)7, (sizeof(t) * 8) - 4))
#define __STILTS_MIN_OF_UNSIGNED_INTEGER_TYPE(t) ((t)0)
#define __STILTS_MIN_OF_SIGNED_INTEGER_TYPE(t) \
    ((t) - ((__STILTS_LIMITS_LEFTSHIFT((t)1, sizeof(t) * 8 - 2) - 1) * 2 + 1) - 1)

#define __STILTS_MAX_OF_INTEGER_TYPE(t)                                       \
    ((t)((__STILTS_IS_TYPE_SIGNED(t) ? __STILTS_MAX_OF_SIGNED_INTEGER_TYPE(t) \
                                     : __STILTS_MAX_OF_UNSIGNED_INTEGER_TYPE(t))))
#define __STILTS_MIN_OF_INTEGER_TYPE(t)                                       \
    ((t)((__STILTS_IS_TYPE_SIGNED(t) ? __STILTS_MIN_OF_SIGNED_INTEGER_TYPE(t) \
                                     : __STILTS_MIN_OF_UNSIGNED_INTEGER_TYPE(t))))

/* Assumes that there are only three floating point types, float, double, and long double.
   Those are the only ones that C defines, but hypothetically other types could exist as an
   extension. Eventually, this should be fixed. */
#define __STILTS_MAX_OF_FLOATING_TYPE(t) \
    _Generic((t)0, float : FLT_MAX, double : DBL_MAX, long double : LDBL_MAX)
#define __STILTS_MIN_OF_FLOATING_TYPE(t) \
    _Generic((t)0, float : FLT_MIN, double : DBL_MIN, long double : LDBL_MIN)

#define __STILTS_MAX_OF_TYPE(t)                                          \
    ((t)(__STILTS_IS_TYPE_FLOATING(t) ? __STILTS_MAX_OF_FLOATING_TYPE(t) \
                                      : __STILTS_MAX_OF_INTEGER_TYPE(t)))
#define __STILTS_MIN_OF_TYPE(t)                                          \
    ((t)(__STILTS_IS_TYPE_FLOATING(t) ? __STILTS_MIN_OF_FLOATING_TYPE(t) \
                                      : __STILTS_MIN_OF_INTEGER_TYPE(t)))

#endif /* __STILTS_STDLIB_LIMITS */
