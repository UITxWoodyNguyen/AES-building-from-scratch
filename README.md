# Lab 2: Building AES from scratch

Bộ thư viện mã hóa khối **AES (FIPS 197)** và các chế độ hoạt động **NIST SP 800-38A, SP 800-38C, SP 800-38D**, tự cài đặt hoàn toàn bằng C++17 tiêu chuẩn (không sử dụng OpenSSL, Crypto++, mbedTLS...).

---

## 1. Cấu trúc thư mục

```
Lab-2/
├── Build_msvc/            # Thư mục build out-of-source cho MSVC
├── Build_gcc/             # Thư mục build out-of-source cho MinGW GCC
├── Build_clang/           # Thư mục build out-of-source cho Clang
├── cmake/                 # CMake helper modules
├── include/
│   ├── aes.h              # Header AES core, T-tables constexpr, secure_zero
│   ├── aes_modes.h        # Header các mode: ECB, CBC, CFB, OFB, CTR, CCM, GCM
│   └── aes_c_api.h        # Pure C API xuất cho Python ctypes / FFI
├── src/
│   ├── aes.cpp            # Cài đặt AES core (T-table, equivalent inverse cipher)
│   ├── aes_modes.cpp      # Cài đặt các chế độ SP 800-38A/C/D
│   ├── aes_c_api.cpp      # Cài đặt C API
│   ├── cpu_features.h/cpp # Runtime CPU feature detection (__cpuid)
│   └── aes_ni.h/cpp       # Đường tối ưu phần cứng AES-NI (tùy chọn)
├── test/
│   ├── test_aes.cpp       # Bộ kiểm thử FIPS 197, SP 800-38A/C/D & Benchmark
│   ├── diff_test.cpp      # Differential testing (1.000.000 block đối chiếu code cũ)
│   ├── old_aes.h/cpp      # Bản AES nguyên bản để đối chiếu
├── python/
│   ├── aeslib.py          # Wrapper Python bằng ctypes (tự tìm DLL, map exception)
│   ├── gui_app.py         # Ứng dụng giao diện PyQt6 (worker QThread, self-test)
│   └── tests/
│       └── test_aeslib.py # Pytest kiểm thử Python binding & cross-validate
├── CMakeLists.txt         # CMake build script chính (≥ 3.21, C++17)
├── CMakePresets.json      # Presets cấu hình, build, test cho 3 compiler
├── build_all.ps1          # Script PowerShell tự động build + ctest 3 compiler
├── Dockerfile             # Multi-stage Dockerfile (build test cả GCC/Clang + headless runtime)
├── .dockerignore
└── README.md
```

---

## 2. Các chế độ hoạt động hỗ trợ

| Chế độ | Tiêu chuẩn | Hỗ trợ kích thước khóa | Ghi chú |
|--------|-----------|------------------------|---------|
| **ECB** | SP 800-38A | 128, 192, 256 bits | Yêu cầu bội số 16B (hỗ trợ PKCS#7 tùy chọn) |
| **CBC** | SP 800-38A | 128, 192, 256 bits | IV 16 bytes ngẫu nhiên |
| **CFB1** | SP 800-38A | 128, 192, 256 bits | Xử lý từng bit |
| **CFB8** | SP 800-38A | 128, 192, 256 bits | Xử lý từng byte (stream cipher) |
| **CFB128** | SP 800-38A | 128, 192, 256 bits | Xử lý từng block 16 bytes |
| **OFB** | SP 800-38A | 128, 192, 256 bits | Mã hóa dòng độc lập bản rõ |
| **CTR** | SP 800-38A | 128, 192, 256 bits | Counter 128-bit tăng tự động |
| **CCM** | SP 800-38C | 128, 192, 256 bits | AEAD: Nonce 7..13B, Tag 4..16B chẵn, AAD tùy ý |
| **GCM** | SP 800-38D | 128, 192, 256 bits | AEAD: IV 96-bit hoặc tùy ý độ dài (GHASH), AAD, Tag 4..16B |

---

## 3. Các kỹ thuật tối ưu hóa

1. **T-Tables tại Compile-Time (`constexpr`)**:
   - Sinh bảng $T_{e0..3}$ và $T_{d0..3}$ ngay lúc compile-time bằng `constexpr`.
   - Gộp SubBytes + ShiftRows + MixColumns thành lookup bảng 32-bit.
2. **Equivalent Inverse Cipher**:
   - Khóa giải mã được áp dụng `InvMixColumns` từ trước (`drk_`), cho phép vòng giải mã có cùng cấu trúc với vòng mã hóa.
3. **Bộ nhớ Big-Endian & Type-punning an toàn**:
   - Dùng `std::memcpy` và dịch bit rõ ràng, tránh vi phạm strict-aliasing và undefined behavior.
4. **Bảo mật bộ nhớ (`secure_zero`)**:
   - Xóa bộ nhớ khóa trong destructor bằng vòng lặp con trỏ `volatile` ngăn compiler optimize mất.
   - So sánh Authentication Tag trong GCM/CCM bằng hàm `constant_time_eq`.
5. **Bảng nhân GHASH tối ưu (8 KB trong L1 Cache)**:
   - Thay vì thuật toán nhân bit chậm, bảng $T[32][16]$ tính trước các lũy thừa của $H$ cho từng nibble vị trí. Mỗi block 16 bytes chỉ cần 32 lần tra bảng và XOR, không cần phép khử mod liên tục.
6. **Tùy chọn AES-NI phần cứng**:
   - Tự động nhận diện CPU tại runtime qua `__cpuid`.
   - Cô lập cờ `-maes -mpclmul -msse4.1` chỉ riêng cho file `aes_ni.cpp`. Luôn có fallback portable chạy được trên mọi CPU x86-64.

> [!WARNING]
> **Cảnh báo bảo mật**: Bản mã hóa phần mềm T-table sử dụng bảng tra cứu bộ nhớ nên về mặt lý thuyết có nguy cơ bị tấn công kênh kề qua bộ nhớ đệm (cache-timing attacks). Đây là bản cài đặt phục vụ mục đích học thuật và nghiên cứu. Đối với môi trường sản xuất, cần kích hoạt đường phần cứng **AES-NI** (chạy thời gian hằng số - constant-time).

---

## 4. Hướng dẫn Biên dịch (3 Compiler)

### 4.1. Tự động biên dịch cả 3 Compiler
Chạy script PowerShell tại thư mục gốc:
```powershell
.\build_all.ps1
```

### 4.2. Biên dịch thủ công từng Compiler

#### Với MinGW GCC:
```powershell
cmake --preset gcc-release
cmake --build --preset gcc-release
cd Build_gcc
ctest --output-on-failure
```

#### Với Clang (LLVM):
```powershell
cmake --preset clang-release
cmake --build --preset clang-release
cd Build_clang
ctest --output-on-failure
```

#### Với Microsoft Visual C++ (MSVC 2026/2022):
```powershell
cmake --preset msvc-release
cmake --build --preset msvc-release
cd Build_msvc
ctest -C Release --output-on-failure
```

---

## 5. Chạy Benchmark

Sau khi build, chạy file `aes_bench`:
```powershell
# Trên GCC
.\Build_gcc\aes_bench.exe --bench

# Trên Clang
.\Build_clang\aes_bench.exe --bench

# Trên MSVC
.\Build_msvc\Release\aes_bench.exe --bench
```

### Bảng kết quả Benchmark thực tế (Dữ liệu 64 MB, CPU Intel Core 11th Gen):

| Chế độ | Throughput (GCC 16) | Throughput (Clang 22) | Throughput (MSVC 19.51) |
|--------|---------------------|-----------------------|-------------------------|
| **ECB Encrypt** | **327.9 MB/s** | **341.2 MB/s** | **315.6 MB/s** |
| **ECB Decrypt** | **311.5 MB/s** | **326.8 MB/s** | **302.1 MB/s** |
| **CBC Encrypt** | **280.9 MB/s** | **289.4 MB/s** | **274.0 MB/s** |
| **CBC Decrypt** | **322.5 MB/s** | **335.1 MB/s** | **310.8 MB/s** |
| **CTR Crypt**   | **266.8 MB/s** | **275.3 MB/s** | **258.4 MB/s** |
| **GCM Encrypt** | **153.0 MB/s** | **162.4 MB/s** | **148.7 MB/s** |
| **CCM Encrypt** | **136.1 MB/s** | **144.5 MB/s** | **130.2 MB/s** |

*(So với bản ban đầu chưa tối ưu ~12 MB/s, phiên bản mới đạt tốc độ tăng gấp > 25 lần).*

---

## 6. Python Binding & Giao diện PyQt6

### 6.1. Cài đặt thư viện Python (nếu chưa có)
```powershell
pip install PyQt6 pytest cryptography
```

### 6.2. Chạy kiểm thử pytest
```powershell
python -m pytest python/tests -v
```
Toàn bộ 15 test cases (bao gồm cross-validate đối chiếu trực tiếp với thư viện `cryptography`) đều vượt qua 100%.

### 6.3. Khởi chạy Ứng dụng Giao diện PyQt6
```powershell
python python/gui_app.py
```

**Tính năng GUI:**
- Hỗ trợ chọn đầy đủ các mode (ECB, CBC, CFB1, CFB8, CFB128, OFB, CTR, GCM, CCM).
- Nhập dữ liệu và khóa ở định dạng Hex hoặc Chuỗi văn bản UTF-8.
- Nút "Generate Key" và "Generate IV" sinh khóa ngẫu nhiên chuẩn mật mã (`secrets`).
- Mã hóa / giải mã văn bản trực tiếp trên giao diện.
- Mã hóa / giải mã File chạy đa luồng (`QThread`), có thanh tiến trình và đo tốc độ throughput (MB/s).
- Tab **Self-Test** cho phép chạy trực tiếp bộ vector NIST KAT ngay trong ứng dụng.

---

## 7. Docker

### 7.1. Build Docker Image (Multi-stage)
```bash
docker build -t aes-suite:latest .
```
Quá trình build image sẽ tự động:
1. Biên dịch và chạy `ctest` bằng **GCC**.
2. Biên dịch và chạy `ctest` bằng **Clang**.
3. Chạy toàn bộ test `pytest` cho Python ctypes binding.
*(Nếu bất kỳ kiểm thử nào thất bại, quá trình build sẽ dừng ngay lập tức).*

### 7.2. Chạy Container (Headless Self-Test)
```bash
docker run --rm -it aes-suite:latest
```

### 7.3. Chạy GUI qua X11 Forwarding (Tùy chọn)
Trên Windows sử dụng VcXsrv / WSLg hoặc trên Linux:
```bash
docker run --rm -it \
    -e DISPLAY=$DISPLAY \
    -v /tmp/.X11-unix:/tmp/.X11-unix \
    --entrypoint python3 \
    aes-suite:latest python/gui_app.py
```

