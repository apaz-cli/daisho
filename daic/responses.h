#ifndef DAIC_RESPONSES_INCLUDE
#define DAIC_RESPONSES_INCLUDE
#include "../stdlib/Daisho.h"

// Inspired by: https://github.com/Gankra/cargo-mommy
// At the insistence of Violet.

#define DAIC_RESPONSES_USER_TERMS "girl", "cutie", "sweetie"
#define DAIC_RESPONSES_USER_POSESSIVE "their"
#define DAIC_RESPONSES_DAIC_TERMS "mommy", "master", "mistress"
#define DAIC_RESPONSES_DAIC_POSESSIVE "her", "their", "its"

// USER, USER_POSESSIVE, DAIC, and DAIC_POSESSIVE will be replaced with a random selection
// from the above. Eventually this should be exported as a config.

#define DAIC_RESPONSES_POSITIVE                                                                    \
    "*Pets your head*", "You're such a smart cookie~", "That's a good USER~",                      \
        "DAIC thinks DAIC_POSESSIVE litle USER earned a big hug~",                                 \
        "Good USER. Your DAIC is so proud of you~",                                                \
        "Aww, what a good USER~. Your DAIC knew you could do it~",                                 \
        "DAIC's so proud of you~. Your DAIC loves you~", "You're DAIC_POSESSIVE's favorite USER~", \
        "Pretty USERs like you make DAIC's day~", "Hehe, what an obedient USER~",                  \
        "This is the point where DAIC gives DAIC_POSESSIVE USER a big hug~",

#define DAIC_RESPONSES_NEGATIVE                                        \
    "Your DAIC believes in you~", "Do you need DAIC's help~?",         \
        "Your DAIC still loves you no matter what~",                   \
        "Oh no did DAIC's little USER make a big mess~?",              \
        "Your DAIC knows DAIC_POSESSIVE little USER can do better~",   \
        "Just a little further, USER~", "Aww, USER. Let's try again~", \
        "Hehe, you're so cute when you're frustrated.~",                \
        "What a cutie. Your DAIC loves watching you squirm.~",         \
        "Sorry to hear about that USER. It's okay, DAIC can wait.~",   \
        "I guess your DAIC will have to punish you for that later.~",

#define DAIC_RESPONSES_EMOJI                                                        \
    "\360\237\245\260", "\360\237\230\230", "\360\237\222\236", "\360\237\222\225", \
        "\360\237\222\226", "\360\237\222\230", "\360\237\253\266", "\342\235\244\357\270\217"

static inline void
daic_print_response(FILE* f, int pn) {
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

    char* emoji[] = {DAIC_RESPONSES_EMOJI};
    size_t emoji_len = _DAI_ARRAY_SIZE(emoji);

    _Dai_Random r = _Dai_Random_new_osrand();

    char* response = pn ? positive[(size_t)_Dai_rand_range_i64(&r, 0, positive_size - 1)]
                        : negative[(size_t)_Dai_rand_range_i64(&r, 0, negative_size - 1)];

    // Iterate over every char, skip over the special tokens, and
    // replace them with a random selection from their list.
    for (size_t i = 0; i < strlen(response); i++) {
        char* current_pos = response + i;
        if (!strcmp(current_pos, "USER_POSESSIVE") && (i += strlen("USER_POSESSIVE"))) {
            fprintf(f, "%s", user_poss[(size_t)_Dai_rand_range_i64(&r, 0, user_poss_len - 1)]);
        } else if (!strcmp(current_pos, "USER") && (i += strlen("USER"))) {
            fprintf(f, "%s", user_term[(size_t)_Dai_rand_range_i64(&r, 0, user_term_len - 1)]);
        } else if (!strcmp(current_pos, "DAIC_POSESSIVE") && (i += strlen("DAIC_POSESSIVE"))) {
            fprintf(f, "%s", daic_poss[(size_t)_Dai_rand_range_i64(&r, 0, daic_poss_len - 1)]);
        } else if (!strcmp(current_pos, "DAIC") && (i += strlen("DAIC"))) {
            fprintf(f, "%s", daic_term[(size_t)_Dai_rand_range_i64(&r, 0, daic_term_len - 1)]);
        }

        else {
            fputc(*current_pos, f);
        }
    }

    fputc(' ', f);
    fprintf(f, "%s\n", emoji[(size_t)_Dai_rand_range_i64(&r, 0, emoji_len - 1)]);
}

#endif /* DAIC_RESPONSES_INCLUDE */
