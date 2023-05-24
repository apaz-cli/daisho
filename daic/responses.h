#ifndef DAIC_RESPONSES_INCLUDE
#define DAIC_RESPONSES_INCLUDE
#include "../stdlib/Daisho.h"

// Inspired by: https://github.com/Gankra/cargo-mommy
// At the insistence of Violet.

#define DAIC_RESPONSES_USER_TERMS "girl", "cutie", "sweetie"
#define DAIC_RESPONSES_USER_POSESSIVE "their"
#define DAIC_RESPONSES_DAIC_TERMS "mommy", "master", "mistress"
#define DAIC_RESPONSES_DAIC_POSESSIVE "her", "their", "its"

// USER_TERM, USER_POSESSIVE, DAIC_TERM, and DAIC_POSSIVE will be replaced with a random selection
// from the above. Eventually this should be exported as a config.

#define DAIC_RESPONSES_POSITIVE                                                                  \
    "*Pets your head*", "You're such a smart cookie~", "That's a good USER_TERM~",               \
        "DAIC_TERM thinks DAIC_POSESSIVE litle USER_TERM earned a big hug~",                     \
        "Good USER_TERM. Your DAIC_TERM is so proud of you~",                                    \
        "Aww, what a good USER_TERM~. Your DAIC_TERM knew you could do it~",                     \
        "DAIC_TERM's so proud of you~. Your DAIC_TERM loves you~",                               \
        "You're DAIC_POSSIVE's favorite USER_TERM~",                                             \
        "Pretty USER_TERMs like you make DAIC_TERM's day~", "Hehe, what an obedient USER_TERM~", \
        "This is the point where DAIC_TERM gives DAIC_POSESSIVE USER_TERM a big hug~",

#define DAIC_RESPONSES_NEGATIVE                                                  \
    "Your DAIC_TERM believes in you~", "Do you need DAIC_TERM's help~?",         \
        "Your DAIC_TERM still loves you no matter what~",                        \
        "Oh no did DAIC_TERM's little USER_TERM make a big mess~?",              \
        "Your DAIC_TERM knows DAIC_POSESSIVE little USER_TERM can do better~",   \
        "Just a little further, USER_TERM~", "Aww, USER_TERM. Let's try again~", \
        "Hehe, you're so cute when you're frustrated~",                          \
        "What a cutie. Your DAIC_TERM loves watching you squirm.~",              \
        "Sorry to hear about that USER_TERM. It's okay, DAIC_TERM can wait.~",   \
        "I guess your DAIC_TERM will have to punish you for that later~",

#define DAIC_RESPONSES_DAIC_EMOJI                                                   \
    "\360\237\245\260", "\360\237\230\230", "\360\237\222\236", "\360\237\222\225", \
        "\360\237\222\226", "\360\237\222\230", "\360\237\253\266", "\342\235\244\357\270\217"

static inline void
daic_print_heart(void) {
    const char* emoji = "";
    fprintf(stderr, "\342\235\244\357\270\217");
}

static inline void
daic_print_response(int pn) {
    char* positive[] = {DAIC_RESPONSES_POSITIVE};
    char* negative[] = {DAIC_RESPONSES_NEGATIVE};
    size_t positive_size = _DAI_ARRAY_SIZE(positive);
    size_t negative_size = _DAI_ARRAY_SIZE(negative);

    char* user_term[] = {DAIC_RESPONSES_USER_TERMS};
    char* user_poss[] = {DAIC_RESPONSES_USER_POSESSIVE};
    char* daic_term[] = {DAIC_RESPONSES_DAIC_TERMS};
    char* daic_poss[] = {DAIC_RESPONSES_DAIC_POSESSIVE};

    size_t user_term_len = _DAI_ARRAY_SIZE(user_term);
    size_t user_poss_len = _DAI_ARRAY_SIZE(user_poss);
    size_t daic_term_len = _DAI_ARRAY_SIZE(daic_term);
    size_t daic_poss_len = _DAI_ARRAY_SIZE(daic_poss);

    _Dai_Random r = _Dai_Random_new_osrand();

    char* response = pn ? positive[(size_t)_Dai_rand_range_i64(&r, 0, positive_size - 1)]
                        : negative[(size_t)_Dai_rand_range_i64(&r, 0, negative_size - 1)];

    for (size_t i = 0; i < strlen(response); i++) {
        char* current_pos = response + i;
        if (!strcmp(current_pos, "USER_TERM") && (i += strlen("USER_TERM"))) {
            fprintf(stderr, "%s", user_term[(size_t)_Dai_rand_range_i64(&r, 0, user_term_len - 1)]);
        } else if (!strcmp(current_pos, "USER_POSESSIVE") && (i += strlen("USER_POSESSIVE"))) {
            fprintf(stderr, "%s", user_poss[(size_t)_Dai_rand_range_i64(&r, 0, user_poss_len - 1)]);
        } else if (!strcmp(current_pos, "DAIC_TERM") && (i += strlen("DAIC_TERM"))) {
            fprintf(stderr, "%s", daic_term[(size_t)_Dai_rand_range_i64(&r, 0, daic_term_len - 1)]);
        } else if (!strcmp(current_pos, "DAIC_POSESSIVE") && (i += strlen("DAIC_POSESSIVE"))) {
            fprintf(stderr, "%s", daic_poss[(size_t)_Dai_rand_range_i64(&r, 0, daic_poss_len - 1)]);
        }

        else {
            fputc(*current_pos, stderr);
        }
    }
}

#endif /* DAIC_RESPONSES_INCLUDE */
