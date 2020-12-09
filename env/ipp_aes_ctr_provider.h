//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  Copyright (c) 2020 Intel Corporation
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#pragma once

#if !defined(ROCKSDB_LITE)

// Includes Intel's Integrated Performance Primitives for Cryptography (IPPCP).
// IPPCP is lightweight cryptography library that is highly-optimized for
// various Intel CPUs.
//
// We use it here to provide an AES-128/192/256 encryption with a CTR mode of
// operation.
//
// Download URL: https://github.com/intel/ipp-crypto.
//

#include <string>

#include "rocksdb/env_encryption.h"

// ipp-crypto AES context structure
typedef struct _cpRijndael128 IppsAESSpec;

namespace ROCKSDB_NAMESPACE {

// AES-128, AES-192, and AES-256 encryptions are all supported.
enum struct KeySize { AES_128 = 16, AES_192 = 24, AES_256 = 32 };

// This encryption provider uses AES block cipher and a CTR mode of operation
// with a cryptographically secure IV that is randomly generated.
//
// Note: a prefix size of 4096 (4K) is chosen for optimal performance.
//
class IppAESCTRProvider : public EncryptionProvider {
 public:
  static constexpr size_t kPrefixSize = 4096;

  static Status CreateProvider(const std::string& id,
                               std::shared_ptr<EncryptionProvider>* provider);

  static const char* kName() { return "IPP_AES"; }

  virtual size_t GetPrefixLength() const override { return kPrefixSize; }

  virtual const char* Name() const override { return kName(); }

  virtual Status AddCipher(const std::string& /*descriptor*/,
                           const char* /*cipher*/, size_t /*len*/,
                           bool /*for_write*/) override;

  virtual Status CreateNewPrefix(const std::string& fname, char* prefix,
                                 size_t prefixLength) const override;

  virtual Status CreateCipherStream(
      const std::string& fname, const EnvOptions& options, Slice& prefix,
      std::unique_ptr<BlockAccessCipherStream>* result) override;

  virtual Status TEST_Initialize() override;

  virtual ~IppAESCTRProvider();

 private:
#if defined(IPPCP) && (defined(HAVE_SSE42) || defined(HAVE_SSE2))
  int ctx_size_;
  KeySize key_size_;
  IppsAESSpec* aes_ctx_;
  IppAESCTRProvider()
      : ctx_size_(0), key_size_(KeySize::AES_256), aes_ctx_(nullptr) {}
#endif
  IppAESCTRProvider(const IppAESCTRProvider&) = delete;
  IppAESCTRProvider& operator=(const IppAESCTRProvider&) = delete;
};

}  // namespace ROCKSDB_NAMESPACE

#endif  // !defined(ROCKSDB_LITE)
