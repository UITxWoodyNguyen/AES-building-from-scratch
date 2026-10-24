/*
 * cpu_features.cpp - Runtime CPU feature detection
 */

#include "cpu_features.h"

#if defined(_MSC_VER)
    #include <intrin.h>
#elif defined(__GNUC__) || defined(__clang__)
    #include <cpuid.h>
#endif

namespace aes_hw {

CpuFeatures detect_cpu_features() {
    CpuFeatures feat = {false, false, false};

#if defined(_MSC_VER)
    int info[4] = {0};
    __cpuid(info, 1);
    int ecx = info[2];
    feat.has_pclmul = (ecx & (1 << 1)) != 0;
    feat.has_sse41  = (ecx & (1 << 19)) != 0;
    feat.has_aesni  = (ecx & (1 << 25)) != 0;
#elif defined(__GNUC__) || defined(__clang__)
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        feat.has_pclmul = (ecx & (1 << 1)) != 0;
        feat.has_sse41  = (ecx & (1 << 19)) != 0;
        feat.has_aesni  = (ecx & (1 << 25)) != 0;
    }
#endif

    return feat;
}

} // namespace aes_hw

