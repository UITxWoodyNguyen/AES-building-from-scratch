#pragma once
#include <cstdint>
#include <stdexcept>

class OldAES {
private:
    int numKey;
    int numRounds;
    uint8_t roundKey[60][4];

    static void bytes_to_state(const uint8_t* input, uint8_t state[4][4]);
    static void state_to_bytes(const uint8_t state[4][4], uint8_t output[16]);
    void key_expansion(const uint8_t* key, int key_bits);
    static uint8_t gmul(uint8_t a, uint8_t b);
    static void rot_word(uint8_t* word);
    static void sub_word(uint8_t* word);
    static void sub_bytes(uint8_t state[4][4]);
    static void shift_rows(uint8_t state[4][4]);
    static void mix_columns(uint8_t state[4][4]);
    void add_round_key(uint8_t state[4][4], int round) const;
    static void inv_sub_bytes(uint8_t state[4][4]);
    static void inv_shift_rows(uint8_t state[4][4]);
    static void inv_mix_columns(uint8_t state[4][4]);

public:
    OldAES();
    OldAES(const uint8_t* key, int key_bits);
    int getNumRounds() const;
    void encrypt(const uint8_t* input, uint8_t* output) const;
    void decrypt(const uint8_t* input, uint8_t* output) const;
};

