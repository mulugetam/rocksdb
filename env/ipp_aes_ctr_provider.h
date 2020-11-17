//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  Copyright (c) 2020 Intel Corporation
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#pragma once

#if !defined(ROCKSDB_LITE)

#if defined(IPPCP) && (defined(HAVE_SSE42) || defined(HAVE_SSE2))

// Includes Intel's Integrated Performance Primitives for Cryptography (IPPCP).
// IPPCP is lightweight cryptography library that is highly-optimized for
// various Intel CPUs.
//
// We use it here to provide an AES-128/192/256 encryption with a CTR mode of
// operation.
//
// Download URL: https://github.com/intel/ipp-crypto.
//
#include <emmintrin.h>
#include <ippcp.h>

#endif  // IPPCP

#include <string>

#include "rocksdb/env_encryption.h"

namespace ROCKSDB_NAMESPACE {

enum struct KeySize { AES_128 = 16, AES_192 = 24, AES_256 = 32 };

#if defined(IPPCP) && (defined(HAVE_SSE42) || defined(HAVE_SSE2))

class IppAESCTRCipherStream : public BlockAccessCipherStream {
 public:
  static constexpr size_t kBlockSize = 16;    // in bytes
  static constexpr size_t kCounterLen = 128;  // in bits

  IppAESCTRCipherStream(IppsAESSpec* aes_ctx, const char* init_vector);

  virtual Status Encrypt(uint64_t fileOffset, char* data,
                         size_t dataSize) override;
  virtual Status Decrypt(uint64_t fileOffset, char* data,
                         size_t dataSize) override;
  virtual size_t BlockSize() override { return kBlockSize; }

 protected:
  // These functions are not needed and will never be called!
  virtual void AllocateScratch(std::string&) override {}
  virtual Status EncryptBlock(uint64_t, char*, char*) override {
    return Status::NotSupported("Operation not supported.");
  }
  virtual Status DecryptBlock(uint64_t, char*, char*) override {
    return Status::NotSupported("Operation not supported.");
  }

 private:
  IppsAESSpec* aes_ctx_;
  __m128i init_vector_;
};

#endif  // IPPCP

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
#endif  // IPPCP
  IppAESCTRProvider(const IppAESCTRProvider&) = delete;
  IppAESCTRProvider& operator=(const IppAESCTRProvider&) = delete;
};

}  // namespace ROCKSDB_NAMESPACE

#endif  // !defined(ROCKSDB_LITE)
