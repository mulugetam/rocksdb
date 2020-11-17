//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  Copyright (c) 2020 Intel Corporation
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#ifndef ROCKSDB_LITE

#include "ipp_aes_ctr_provider.h"

#include "util/string_util.h"

#endif

namespace ROCKSDB_NAMESPACE {

#ifndef ROCKSDB_LITE

Status IppAESCTRProvider::CreateProvider(
    const std::string& id, std::shared_ptr<EncryptionProvider>* provider) {
  if (id != kName()) {
    return Status::NotSupported("Invalid provider ", id);
  }
#if defined(IPPCP) && (defined(HAVE_SSE42) || defined(HAVE_SSE2))
  IppAESCTRProvider* ptr_ipp = new IppAESCTRProvider();
  provider->reset(ptr_ipp);
  return Status::OK();
#else
  (void)id;
  (void)provider;
  return Status::Aborted("ipp-crypto library not found and requires SSE2+.");
#endif  // IPPCP
}

Status IppAESCTRProvider::AddCipher(const std::string& /*descriptor*/,
                                    const char* cipher, size_t len,
                                    bool /*for_write*/) {
#if defined(IPPCP) && (defined(HAVE_SSE42) || defined(HAVE_SSE2))
  // We currently don't support more than one encryption key
  if (aes_ctx_ != nullptr) {
    return Status::NotSupported("Multiple encryption keys not supported.");
  }

  // AES supports key sizes of only 16, 24, or 32 bytes
  if (len != 16 && len != 24 && len != 32) {
    return Status::NotSupported("Invalid key size in provider.");
  }

  size_t key_size = std::string(cipher).size();
  if (key_size != len) {
    return Status::NotSupported("Key size mismatch in provider.");
  }

  // key_size is in bytes
  switch (key_size) {
    case 16:
      key_size_ = KeySize::AES_128;
      break;
    case 24:
      key_size_ = KeySize::AES_192;
      break;
    case 32:
      key_size_ = KeySize::AES_256;
      break;
  }

  // get size for context
  IppStatus ipp_status = ippsAESGetSize(&ctx_size_);
  if (ipp_status != ippStsNoErr) {
    return Status::Aborted("Failed to create provider.");
  }

  // allocate memory for context
  aes_ctx_ = (IppsAESSpec*)(new Ipp8u[ctx_size_]);
  assert(aes_ctx_ != nullptr);

  // initialize context
  const Ipp8u* key = (const Ipp8u*)(cipher);
  ipp_status =
      ippsAESInit(key, static_cast<int>(key_size_), aes_ctx_, ctx_size_);

  if (ipp_status != ippStsNoErr) {
    // clean up context and abort!
    ippsAESInit(0, static_cast<int>(key_size_), aes_ctx_, ctx_size_);
    delete[](Ipp8u*) aes_ctx_;
    return Status::Aborted("Failed to create provider.");
  }
#else
  (void)cipher;
  (void)len;
#endif  // IPPCP
  return Status::OK();
}

Status IppAESCTRProvider::TEST_Initialize() {
  return AddCipher("", "a6d2ae2816157e2b3c4fcf098815f7xb", 32, false);
}

Status IppAESCTRProvider::CreateNewPrefix(const std::string& /*fname*/,
                                          char* prefix,
                                          size_t prefixLength) const {
#if defined(IPPCP) && (defined(HAVE_SSE42) || defined(HAVE_SSE2))
  IppStatus ipp_status;
  Ipp32u rnd;
  const size_t rnd_size = sizeof(Ipp32u);
  assert(prefixLength % rnd_size == 0);
  for (size_t i = 0; i < prefixLength; i += rnd_size) {
    ipp_status = ippsPRNGenRDRAND(&rnd, rnd_size << 3, nullptr);
    if (ipp_status != ippStsNoErr)
      return Status::Aborted(ippcpGetStatusString(ipp_status));
    memcpy(prefix + i, &rnd, rnd_size);
  }
  IppAESCTRCipherStream cs(aes_ctx_, prefix);
  return cs.Encrypt(0, prefix + IppAESCTRCipherStream::kBlockSize,
                    prefixLength - IppAESCTRCipherStream::kBlockSize);
#else
  (void)prefix;
  (void)prefixLength;
  return Status::OK();
#endif  // IPPCP
}

Status IppAESCTRProvider::CreateCipherStream(
    const std::string& /*fname*/, const EnvOptions& /*options*/, Slice& prefix,
    std::unique_ptr<BlockAccessCipherStream>* result) {
#if defined(IPPCP) && (defined(HAVE_SSE42) || defined(HAVE_SSE2))
  assert(result != nullptr);
  assert(prefix.size() >= IppAESCTRCipherStream::kBlockSize);
  result->reset(new IppAESCTRCipherStream(aes_ctx_, prefix.data()));
  Status ipp_status = (*result)->Decrypt(
      0, (char*)prefix.data() + IppAESCTRCipherStream::kBlockSize,
      prefix.size() - IppAESCTRCipherStream::kBlockSize);
  return ipp_status;
#else
  (void)prefix;
  (void)result;
  return Status::OK();
#endif  // IPPCP
}

IppAESCTRProvider::~IppAESCTRProvider() {
#if defined(IPPCP) && (defined(HAVE_SSE42) || defined(HAVE_SSE2))
  ippsAESInit(0, static_cast<int>(key_size_), aes_ctx_, ctx_size_);
  delete[](Ipp8u*) aes_ctx_;
#endif  // IPPCP
}

#if defined(IPPCP) && (defined(HAVE_SSE42) || defined(HAVE_SSE2))

IppAESCTRCipherStream::IppAESCTRCipherStream(IppsAESSpec* aes_ctx,
                                             const char* init_vector)
    : aes_ctx_(aes_ctx) {
  init_vector_ = _mm_loadu_si128((__m128i*)init_vector);
}

Status IppAESCTRCipherStream::Encrypt(uint64_t fileOffset, char* data,
                                      size_t dataSize) {
  if (dataSize == 0) return Status::OK();

  size_t index = fileOffset / kBlockSize;
  size_t offset = fileOffset % kBlockSize;

  Ipp8u ctr_block[kBlockSize];

  __m128i counter = _mm_add_epi64(init_vector_, _mm_cvtsi64_si128(index));
  Ipp8u* ptr_counter = (Ipp8u*)&counter;
  for (size_t i = 0; i < kBlockSize; ++i)
    ctr_block[i] = ptr_counter[kBlockSize - 1 - i];

  IppStatus ipp_status = ippStsNoErr;
  if (offset == 0) {
    ipp_status = ippsAESEncryptCTR((Ipp8u*)(data), (Ipp8u*)data, dataSize,
                                   aes_ctx_, ctr_block, kCounterLen);
  } else {
    Ipp8u zero_block[kBlockSize]{0};
    ipp_status = ippsAESEncryptCTR(zero_block, zero_block, kBlockSize, aes_ctx_,
                                   ctr_block, kCounterLen);
    size_t n = std::min(kBlockSize - offset, dataSize);
    for (size_t i = 0; i < n; ++i) data[i] ^= zero_block[offset + i];
    memset(zero_block, 0, kBlockSize);

    n = kBlockSize - offset;
    if (dataSize > n) {
      Ipp8u* ptr = (Ipp8u*)(data + n);
      ipp_status = ippsAESEncryptCTR(ptr, ptr, dataSize - n, aes_ctx_,
                                     ctr_block, kCounterLen);
    }
  }

  if (ipp_status == ippStsNoErr) return Status::OK();

  return Status::Aborted(ippcpGetStatusString(ipp_status));
}

Status IppAESCTRCipherStream::Decrypt(uint64_t fileOffset, char* data,
                                      size_t dataSize) {
  return Encrypt(fileOffset, data, dataSize);
}

#endif  // IPPCP

#endif  // ROCKSDB_LITE

}  // namespace ROCKSDB_NAMESPACE
