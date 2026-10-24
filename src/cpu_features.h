/*
 * cpu_features.h - Runtime CPU feature detection for x86-64
 */

#ifndef CPU_FEATURES_H_INCLUDED
#define CPU_FEATURES_H_INCLUDED

namespace aes_hw {

struct CpuFeatures {
    bool has_aesni;
    bool has_pclmul;
    bool has_sse41;
};

// Returns CPU features detected at runtime
CpuFeatures detect_cpu_features();

} // namespace aes_hw

#endif // CPU_FEATURES_H_INCLUDED

