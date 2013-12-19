// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2013 Cloudwatt <libre.licensing@cloudwatt.com>
 *               2013 CERN/Switzerland
 *
 * Authors: Loic Dachary <loic@dachary.org>
 *          Andreas-Joachim Peters <andreas.joachim.peters@cern.ch> 
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 * 
 */

#include <errno.h>
#include <algorithm>
#include "common/debug.h"
#include "ErasureCodeJerasure.h"
#include "ErasureCodeLocalParity.h"
#include "vectorop.h"

extern "C"
{
#include "jerasure.h"
#include "reed_sol.h"
#include "galois.h"
#include "cauchy.h"
#include "liberation.h"
}

#define dout_subsys ceph_subsys_osd
#undef dout_prefix
#define dout_prefix _prefix(_dout)

static ostream&
_prefix (std::ostream* _dout)
{
  return *_dout << "ErasureCodeJerasure: ";
}

void
ErasureCodeJerasure::init (const map<std::string, std::string> &parameters)
{
  dout(10) << "technique=" << technique << dendl;
  parse(parameters);
  prepare();
}

int
ErasureCodeJerasure::minimum_to_decode (const set<int> &want_to_read,
                                        const set<int> &available_chunks,
                                        set<int> *minimum)
{
  set<int>::iterator i;
  set<int>::iterator o;

  if (!lp) {
    // -------------------------------------------------------------------------
    // no local parity
    // -------------------------------------------------------------------------
    if (includes(available_chunks.begin(), available_chunks.end(),
                 want_to_read.begin(), want_to_read.end())) {
      *minimum = want_to_read;
    }
    else {
      if (available_chunks.size() < (unsigned) k)
        return -EIO;
      set<int>::iterator i;
      unsigned j;
      for (i = available_chunks.begin(), j = 0; j < (unsigned) k; i++, j++)
        minimum->insert(*i);
    }
    return 0;
  }
  else {
    // -------------------------------------------------------------------------
    // basic pyramid code:local parity
    // -------------------------------------------------------------------------
    ErasureCodeLocalParity ecParity(0, 0, k, m, lp, 0);
    return ecParity.minimum_to_decode(want_to_read,
                                      available_chunks,
                                      minimum);
  }
}

int
ErasureCodeJerasure::minimum_to_decode_with_cost (const set<int> &want_to_read,
                                                  const map<int, int> &available,
                                                  set<int> *minimum)
{
  set <int> available_chunks;
  for (map<int, int>::const_iterator i = available.begin();
    i != available.end();
    i++)
    available_chunks.insert(i->first);
  return minimum_to_decode(want_to_read, available_chunks, minimum);
}

int
ErasureCodeJerasure::encode (const set<int> &want_to_encode,
                             const bufferlist &in,
                             map<int, bufferlist> *encoded)
{
  unsigned alignment = get_alignment();
  unsigned tail = in.length() % alignment;
  unsigned padded_length = in.length() + (tail ? (alignment - tail) : 0);
  dout(10) << "encode adjusted buffer length from " << in.length()
    << " to " << padded_length << dendl;
  assert(padded_length % k == 0);
  unsigned blocksize = padded_length / k;
  unsigned length = blocksize * (k + m + lp);
  bufferlist out(in);

  bufferptr pad(length - in.length());
  pad.zero(0, padded_length - in.length());
  out.push_back(pad);
  char *chunks[k + m + lp];
  for (int i = 0; i < k + m + lp; i++) {
    bufferlist &chunk = (*encoded)[i];
    chunk.substr_of(out, i * blocksize, blocksize);
    chunks[i] = chunk.c_str();
  }

  bool encode_erasure = false;
  bool encode_lp = false;
  // ---------------------------------------------------------------------------
  // check if we need to do erasure encoding and/or local parity encoding
  // ---------------------------------------------------------------------------
  for (int j = 0; j < (int) want_to_encode.size(); j++) {
    encode_erasure |= (j < k) ? true : false;
    encode_lp |= (j >= k) ? true : false;
  }

  // ---------------------------------------------------------------------------
  // if needed do erasure encoding : jerasure
  // ---------------------------------------------------------------------------
  if (encode_erasure) jerasure_encode(&chunks[0], &chunks[k], blocksize);
  // ---------------------------------------------------------------------------
  // if needed do local parity encoding : basic pyramid code
  // ---------------------------------------------------------------------------
  if (encode_lp && lp) {
    ErasureCodeLocalParity ecParity(&chunks[0], &chunks[k + m],
                                    k, m, lp, blocksize);
    ecParity.generate();
  }

  for (int i = 0; i < k + m + lp; i++) {
    if (!want_to_encode.count(i))
      encoded->erase(i);
  }
  return 0;
}

int
ErasureCodeJerasure::decode (const set<int> &want_to_read,
                             const map<int, bufferlist> &chunks,
                             map<int, bufferlist> *decoded)
{
  unsigned blocksize = (*chunks.begin()).second.length();
  int erasures[k + m + lp + 1];
  int erasures_count = 0;
  std::set<int>remaining_erasures;
  char *data[k];
  char *coding[m + lp];
  for (int i = 0; i < k + m + lp; i++) {
    (*decoded)[i].clear();

    if (chunks.find(i) == chunks.end()) {
      erasures[erasures_count] = i;
      remaining_erasures.insert(i);
      erasures_count++;
      bufferptr ptr(blocksize);
      (*decoded)[i].push_front(ptr);
    }
    else {
      (*decoded)[i] = chunks.find(i)->second;
    }
    if (i < k)
      data[i] = (*decoded)[i].c_str();
    else
      coding[i - k] = (*decoded)[i].c_str();
  }
  erasures[erasures_count] = -1;

  if (erasures_count > 0) {
    // -------------------------------------------------------------------------
    // try first with local parity : basic pyramid code
    // -------------------------------------------------------------------------
    if (lp) {
      ErasureCodeLocalParity ecParity(data, coding, k, m, lp, blocksize);
      if (ecParity.reconstruct(remaining_erasures, want_to_read))
        return 0;
      // -----------------------------------------------------------------------
      // local parity was not enough ...
      // rewrite the erasures array with the remaining blocks to repair
      // -----------------------------------------------------------------------
      int i = 0;
      for (std::set<int>::iterator it = remaining_erasures.begin();
        it != remaining_erasures.end();
        ++it, ++i) {
        erasures[i] = *it;
      }
      erasures[i] = -1;
    }
    // -------------------------------------------------------------------------
    // do erasure decoding 
    // -------------------------------------------------------------------------
    int rc=0;
    if ((rc = jerasure_decode(erasures, data, coding, blocksize)) ) {
      (*decoded).clear();
    }
    return rc;
  }
  else {
    return 0;
  }
}

int
ErasureCodeJerasure::to_int (const std::string &name,
                             const map<std::string, std::string> &parameters,
                             int default_value)
{
  if (parameters.find(name) == parameters.end() ||
      parameters.find(name)->second.size() == 0) {
    dout(10) << name << " defaults to " << default_value << dendl;
    return default_value;
  }
  const std::string value = parameters.find(name)->second;
  std::string p = value;
  std::string err;
  int r = strict_strtol(p.c_str(), 10, &err);
  if (!err.empty()) {
    derr << "could not convert " << name << "=" << value
      << " to int because " << err
      << ", set to default " << default_value << dendl;
    return default_value;
  }
  dout(10) << name << " set to " << r << dendl;
  return r;
}

bool
ErasureCodeJerasure::is_prime (int value)
{
  int prime55[] = {
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
    151, 157, 163, 167, 173, 179,
    181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257
  };
  int i;
  for (i = 0; i < 55; i++)
    if (value == prime55[i])
      return true;
  return false;
}

// 
// ErasureCodeJerasureReedSolomonVandermonde
//

void
ErasureCodeJerasureReedSolomonVandermonde::jerasure_encode (char **data,
                                                            char **coding,
                                                            int blocksize)
{
  jerasure_matrix_encode(k, m, w, matrix, data, coding, blocksize);
}

int
ErasureCodeJerasureReedSolomonVandermonde::jerasure_decode (int *erasures,
                                                            char **data,
                                                            char **coding,
                                                            int blocksize)
{
  return jerasure_matrix_decode(k, m, w, matrix, 1,
                                erasures, data, coding, blocksize);
}

unsigned
ErasureCodeJerasureReedSolomonVandermonde::get_alignment ()
{
  return k * w * LARGEST_VECTOR_WORDSIZE;
}

void
ErasureCodeJerasureReedSolomonVandermonde::parse (const map<std::string, std::string> &parameters)
{
  k = to_int("erasure-code-k", parameters, DEFAULT_K);
  m = to_int("erasure-code-m", parameters, DEFAULT_M);
  w = to_int("erasure-code-w", parameters, DEFAULT_W);
  lp = to_int("erasure-code-lp", parameters, DEFAULT_LOCAL_PARITY);

  if (w != 8 && w != 16 && w != 32) {
    derr << "ReedSolomonVandermonde: w=" << w
      << " must be one of {8, 16, 32} : revert to 8 " << dendl;
    w = 8;
  }
  if (lp > k) {
    lp = DEFAULT_LOCAL_PARITY;
    derr << "lp=" << lp << " must be less than or equal to k=" << k << " : reverting to lp=" << lp << dendl;
  }
}

void
ErasureCodeJerasureReedSolomonVandermonde::prepare ()
{
  matrix = reed_sol_vandermonde_coding_matrix(k, m, w);
}

// 
// ErasureCodeJerasureReedSolomonRAID6
//

void
ErasureCodeJerasureReedSolomonRAID6::jerasure_encode (char **data,
                                                      char **coding,
                                                      int blocksize)
{
  reed_sol_r6_encode(k, w, data, coding, blocksize);
}

int
ErasureCodeJerasureReedSolomonRAID6::jerasure_decode (int *erasures,
                                                      char **data,
                                                      char **coding,
                                                      int blocksize)
{
  return jerasure_matrix_decode(k, m, w, matrix, 1, erasures, data, coding, blocksize);
}

unsigned
ErasureCodeJerasureReedSolomonRAID6::get_alignment ()
{
  return k * w * LARGEST_VECTOR_WORDSIZE;
}

void
ErasureCodeJerasureReedSolomonRAID6::parse (const map<std::string, std::string> &parameters)
{
  k = to_int("erasure-code-k", parameters, DEFAULT_K);
  m = 2;
  w = to_int("erasure-code-w", parameters, DEFAULT_W);
  lp = to_int("erasure-code-lp", parameters, DEFAULT_LOCAL_PARITY);

  if (w != 8 && w != 16 && w != 32) {
    derr << "ReedSolomonRAID6: w=" << w
      << " must be one of {8, 16, 32} : revert to 8 " << dendl;
    w = 8;
  }
  if (lp > k) {
    lp = DEFAULT_LOCAL_PARITY;
    derr << "lp=" << lp << " must be less than or equal to k=" << k << " : reverting to lp=" << lp << dendl;
  }
}

void
ErasureCodeJerasureReedSolomonRAID6::prepare ()
{
  matrix = reed_sol_r6_coding_matrix(k, w);
}

// 
// ErasureCodeJerasureCauchy
//

void
ErasureCodeJerasureCauchy::jerasure_encode (char **data,
                                            char **coding,
                                            int blocksize)
{
  jerasure_schedule_encode(k, m, w, schedule,
                           data, coding, blocksize, packetsize);
}

int
ErasureCodeJerasureCauchy::jerasure_decode (int *erasures,
                                            char **data,
                                            char **coding,
                                            int blocksize)
{
  return jerasure_schedule_decode_lazy(k, m, w, bitmatrix,
                                       erasures, data, coding, blocksize, packetsize, 1);
}

unsigned
ErasureCodeJerasureCauchy::get_alignment ()
{
  return k * w * packetsize * (packetsize%LARGEST_VECTOR_WORDSIZE)?LARGEST_VECTOR_WORDSIZE:1;
}

void
ErasureCodeJerasureCauchy::parse (const map<std::string, std::string> &parameters)
{
  k = to_int("erasure-code-k", parameters, DEFAULT_K);
  m = to_int("erasure-code-m", parameters, DEFAULT_M);
  w = to_int("erasure-code-w", parameters, DEFAULT_W);
  packetsize = to_int("erasure-code-packetsize", parameters, DEFAULT_PACKETSIZE);
  lp = to_int("erasure-code-lp", parameters, DEFAULT_LOCAL_PARITY);
  if (lp > k) {
    lp = DEFAULT_LOCAL_PARITY;
    derr << "lp=" << lp << " must be less than or equal to k=" << k << " : reverting to lp=" << lp << dendl;
  }
}

void
ErasureCodeJerasureCauchy::prepare_schedule (int *matrix)
{
  bitmatrix = jerasure_matrix_to_bitmatrix(k, m, w, matrix);
  schedule = jerasure_smart_bitmatrix_to_schedule(k, m, w, bitmatrix);
}

// 
// ErasureCodeJerasureCauchyOrig
//

void
ErasureCodeJerasureCauchyOrig::prepare ()
{
  int *matrix = cauchy_original_coding_matrix(k, m, w);
  prepare_schedule(matrix);
  free(matrix);
}

// 
// ErasureCodeJerasureCauchyGood
//

void
ErasureCodeJerasureCauchyGood::prepare ()
{
  int *matrix = cauchy_good_general_coding_matrix(k, m, w);
  prepare_schedule(matrix);
  free(matrix);
}

// 
// ErasureCodeJerasureLiberation
//

ErasureCodeJerasureLiberation::~ErasureCodeJerasureLiberation ()
{
  if (bitmatrix)
    free(bitmatrix);
  if (schedule)
    jerasure_free_schedule(schedule);
}

void
ErasureCodeJerasureLiberation::jerasure_encode (char **data,
                                                char **coding,
                                                int blocksize)
{
  jerasure_schedule_encode(k, m, w, schedule, data,
                           coding, blocksize, packetsize);
}

int
ErasureCodeJerasureLiberation::jerasure_decode (int *erasures,
                                                char **data,
                                                char **coding,
                                                int blocksize)
{
  return jerasure_schedule_decode_lazy(k, m, w, bitmatrix, erasures, data,
                                       coding, blocksize, packetsize, 1);
}

unsigned
ErasureCodeJerasureLiberation::get_alignment ()
{
  return k * w * packetsize * (packetsize%LARGEST_VECTOR_WORDSIZE)?LARGEST_VECTOR_WORDSIZE:1;
}

void
ErasureCodeJerasureLiberation::parse (const map<std::string, std::string> &parameters)
{
  k = to_int("erasure-code-k", parameters, DEFAULT_K);
  m = to_int("erasure-code-m", parameters, DEFAULT_M);
  w = to_int("erasure-code-w", parameters, DEFAULT_W);
  packetsize = to_int("erasure-code-packetsize", parameters, DEFAULT_PACKETSIZE);
  lp = to_int("erasure-code-lp", parameters, DEFAULT_LOCAL_PARITY);

  bool error = false;
  if (k > w) {
    derr << "k=" << k << " must be less than or equal to w=" << w << dendl;
    error = true;
  }
  if (w <= 2 || !is_prime(w)) {
    derr << "w=" << w << " must be greater than two and be prime" << dendl;
    error = true;
  }
  if (packetsize == 0) {
    derr << "packetsize=" << packetsize << " must be set" << dendl;
    error = true;
  }
  if ((packetsize % (sizeof (int))) != 0) {
    derr << "packetsize=" << packetsize
      << " must be a multiple of sizeof(int) = " << sizeof (int) << dendl;
    error = true;
  }
  if (lp > k) {
    lp = DEFAULT_LOCAL_PARITY;
    derr << "lp=" << lp << " must be less than or equal to k=" << k << " : reverting to lp=" << lp << dendl;
  }
  if (error) {
    derr << "reverting to k=" << DEFAULT_K << ", w="
      << DEFAULT_W << ", packetsize=" << DEFAULT_PACKETSIZE << dendl;
    k = DEFAULT_K;
    w = DEFAULT_W;
    packetsize = DEFAULT_PACKETSIZE;
  }
}

void
ErasureCodeJerasureLiberation::prepare ()
{
  bitmatrix = liberation_coding_bitmatrix(k, w);
  schedule = jerasure_smart_bitmatrix_to_schedule(k, m, w, bitmatrix);
}

// 
// ErasureCodeJerasureBlaumRoth
//

void
ErasureCodeJerasureBlaumRoth::prepare ()
{
  bitmatrix = blaum_roth_coding_bitmatrix(k, w);
  schedule = jerasure_smart_bitmatrix_to_schedule(k, m, w, bitmatrix);
}


// 
// ErasureCodeJerasureLiber8tion
//

void
ErasureCodeJerasureLiber8tion::parse (const map<std::string, std::string> &parameters)
{
  k = to_int("erasure-code-k", parameters, DEFAULT_K);
  m = DEFAULT_M;
  w = DEFAULT_W;
  packetsize = to_int("erasure-code-packetsize", parameters, DEFAULT_PACKETSIZE);
  lp = to_int("erasure-code-lp", parameters, DEFAULT_LOCAL_PARITY);

  bool error = false;
  if (k > w) {
    derr << "k=" << k << " must be less than or equal to w=" << w << dendl;
    error = true;
  }
  if (packetsize == 0) {
    derr << "packetsize=" << packetsize << " must be set" << dendl;
    error = true;
  }
  if (lp > k) {
    lp = DEFAULT_LOCAL_PARITY;
    derr << "lp=" << lp << " must be less than or equal to k=" << k << " : reverting to lp=" << lp << dendl;
  }
  if (error) {
    derr << "reverting to k=" << DEFAULT_K << ", packetsize="
      << DEFAULT_PACKETSIZE << dendl;
    k = DEFAULT_K;
    packetsize = DEFAULT_PACKETSIZE;
  }
}

void
ErasureCodeJerasureLiber8tion::prepare ()
{
  bitmatrix = liber8tion_coding_bitmatrix(k);
  schedule = jerasure_smart_bitmatrix_to_schedule(k, m, w, bitmatrix);
}

// 
// ErasureCodeIntelIsa
//

void
ErasureCodeIntelIsa::parse (const map<std::string, std::string> &parameters)
{
  k = to_int("erasure-code-k", parameters, DEFAULT_K);
  m = to_int("erasure-code-m", parameters, DEFAULT_M);
  lp = to_int("erasure-code-lp", parameters, DEFAULT_LOCAL_PARITY);

  if (lp > k) {
    derr << "lp=" << lp << " must be less than or equal to k=" << k << " : reverting to lp=" << DEFAULT_LOCAL_PARITY << dendl;
    lp = DEFAULT_LOCAL_PARITY;
  }

  if (k > 64) {
    derr << "k=" << k << " must be less than or equal to k=64 : reverting to k=" << DEFAULT_K << dendl;
    k = DEFAULT_K;
  }
  
  if ( (k+m) > 64) {
    derr << "(m+k)=" << (m+k) << " must be less than or equal to (m+k)=96 : reverting to m=" << (96-k) << dendl;
    m = 96-k;
  }

  std::string isa_lib ="";

  if (parameters.find("intel-isa-lib")!=parameters.end()) {
    isa_lib = parameters.find("intel-isa-lib")->second;
  } else {
    isa_lib = "isa-l.so";
  }

  IsaLibrary = dlopen(isa_lib.c_str(), RTLD_LAZY);
  if (!IsaLibrary) {
    derr << "unable to open isa-library " << isa_lib << dendl;
  } else {
    Isa_GenRsMatrix    = (void (*)(unsigned char*, int, int))dlsym(IsaLibrary,"gf_gen_rs_matrix");
    Isa_GfInvertMatrix = (int  (*)(unsigned char *, unsigned char *, int ))dlsym(IsaLibrary,"gf_invert_matrix");
    Isa_EcInitTables   = (void (*)(int, int, unsigned char*, unsigned char*))dlsym(IsaLibrary,"ec_init_tables");
    Isa_EcEncodeData   = (void (*)(int, int, int, unsigned char*, unsigned char**, unsigned char**))dlsym(IsaLibrary,"ec_encode_data");
    
    assert(Isa_GenRsMatrix);
    assert(Isa_GfInvertMatrix);
    assert(Isa_EcInitTables);
    assert(Isa_EcEncodeData);
  }
  assert(IsaLibrary);
}

void
ErasureCodeIntelIsa::prepare ()
{
  (*Isa_GenRsMatrix)(a, k+m, k);
  (*Isa_EcInitTables)(k,m,&a[k*k], g_tbls);
}

unsigned
ErasureCodeIntelIsa::get_alignment ()
{
  return k * m * 64;
}

void
ErasureCodeIntelIsa::jerasure_encode (char **data,
				      char **coding,
				      int blocksize)
{
  (Isa_EcEncodeData)(blocksize, k, m, g_tbls, (unsigned char**)data, (unsigned char**)coding);
  return;
}

bool
ErasureCodeIntelIsa::erasure_contains(int *erasures, int i)
{
  for (int l=0; erasures[l]!=-1; l++) {
    if (erasures[l] == i)
      return true;
  }
  return false;
}
int
ErasureCodeIntelIsa::jerasure_decode (int *erasures,
				      char **data,
				      char **coding,
				      int blocksize)
{
  int nerrs=0;
  int i,j,r,s;
  // count the errors 
  for (int l=0; erasures[l]!=-1; l++) {
    nerrs++;
  }
  unsigned char *recover_source[64];
  unsigned char *recover_target[64];
  memset(recover_source,0, sizeof(recover_source));
  memset(recover_target,0, sizeof(recover_target));

  if (nerrs > m) 
    return -1;

  // Construct b by removing error rows

  for(i=0, r=0; i<k; i++, r++) {
    while (erasure_contains(erasures,r))
      r++;
    for(j=0; j<k; j++)
      b[k*i+j] = a[k*r+j];
  }
  
  if ((*Isa_GfInvertMatrix)(b, d, k) < 0){
    printf("BAD MATRIX\n");
    return -1;
  }

  for(i=0, r=0, s=0; i<k; i++, r++){
    while (erasure_contains(erasures,r)) {
      if (r<k) {
	recover_target[s] = (unsigned char*)data[r];
      } else {
	recover_target[s] = (unsigned char*)coding[r-k];
      }
      r++;
      s++;
    }
    if (r<k) {
      recover_source[i] = (unsigned char*)data[r];
    }
    else {
      recover_source[i] = (unsigned char*)coding[r-k];
    }
  }

  for(i=0; i<nerrs; i++){
    for(j=0; j<k; j++){
      c[k*i+j]=d[k*erasures[i]+j];
    }
  }
  
  // Recover data
  (*Isa_EcInitTables)(k, nerrs, c, g_tbls);
  (*Isa_EcEncodeData)(blocksize,
			     k, nerrs, g_tbls, recover_source, recover_target);
  return 0;
}

// 
