# ============================================================
#  Stage 1: Build & Verify (GCC + Clang + ctest + pytest)
# ============================================================
FROM debian:bookworm-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    cmake \
    ninja-build \
    python3 \
    python3-pip \
    python3-pytest \
    python3-cryptography \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Copy source repository
COPY . /workspace

# 1. Build and verify with GCC
RUN cmake -B build_gcc -G Ninja \
    -DCMAKE_C_COMPILER=gcc \
    -DCMAKE_CXX_COMPILER=g++ \
    -DCMAKE_BUILD_TYPE=Release \
    -DAES_ENABLE_AESNI=ON \
    -DAES_BUILD_TESTS=ON \
    && cmake --build build_gcc \
    && cd build_gcc && ctest --output-on-failure

# 2. Build and verify with Clang
RUN cmake -B build_clang -G Ninja \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_BUILD_TYPE=Release \
    -DAES_ENABLE_AESNI=ON \
    -DAES_BUILD_TESTS=ON \
    && cmake --build build_clang \
    && cd build_clang && ctest --output-on-failure

# 3. Verify Python ctypes binding with pytest
ENV AES_LIB_PATH=/workspace/build_gcc/libaes_shared.so
RUN python3 -m pytest python/tests -v

# ============================================================
#  Stage 2: Minimal Runtime (Headless + Non-root)
# ============================================================
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-cryptography \
    python3-pytest \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 aesuser

WORKDIR /home/aesuser/app

# Copy shared library and Python modules
COPY --from=builder /workspace/build_gcc/libaes_shared.so /usr/local/lib/libaes_shared.so
RUN ldconfig

COPY --chown=aesuser:aesuser python/ /home/aesuser/app/python/

ENV AES_LIB_PATH=/usr/local/lib/libaes_shared.so
ENV PYTHONPATH=/home/aesuser/app/python

USER aesuser

# Default entrypoint: Run test suite & demo
ENTRYPOINT ["python3", "-m", "pytest", "/home/aesuser/app/python/tests", "-v"]

