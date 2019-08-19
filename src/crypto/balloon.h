// https://github.com/itwysgsl/balloon/

#ifndef BALLOON_H
#define BALLOON_H

#define S_COST (uint64_t)64
#define T_COST (uint64_t)16
#define DELTA  (uint64_t)7

#ifdef __cplusplus
extern "C" {
#endif

void balloon_blake(const unsigned char* input, char* output, int length, const unsigned char* salt, int salt_length);

#ifdef __cplusplus
}
#endif

#endif
