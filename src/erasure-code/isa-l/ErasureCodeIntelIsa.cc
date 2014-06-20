/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2014 CERN (Switzerland)
 *
 * Author: Andreas-Joachim Peters <Andreas.Joachim.Peters@cern.ch>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 * 
 */

// -----------------------------------------------------------------------------
#include <algorithm>
#include <dlfcn.h>
#include <errno.h>
// -----------------------------------------------------------------------------
#include "common/debug.h"
#include "ErasureCodeIntelIsa.h"
#include "crush/CrushWrapper.h"
#include "osd/osd_types.h"
// -----------------------------------------------------------------------------
extern "C" {
#include "isa-l/include/erasure_code.h"
}
// -----------------------------------------------------------------------------
#define dout_subsys ceph_subsys_osd
#undef dout_prefix
#define dout_prefix _prefix(_dout)
// -----------------------------------------------------------------------------
Mutex ErasureCodeIntelIsaDefault::IsaLibraryMutex ("isa-l");
void* ErasureCodeIntelIsaDefault::IsaLibrary = 0;
// -----------------------------------------------------------------------------

static ostream&
_prefix(std::ostream* _dout)
{
  return *_dout << "ErasureCodeIntelIsa: ";
}
// -----------------------------------------------------------------------------

int
ErasureCodeIntelIsa::create_ruleset(const string &name,
                                    CrushWrapper &crush,
                                    ostream *ss) const
{
  return crush.add_simple_ruleset(name, ruleset_root, ruleset_failure_domain,
                                  "indep", pg_pool_t::TYPE_ERASURE, ss);
}

// -----------------------------------------------------------------------------

void
ErasureCodeIntelIsa::init(const map<string, string> &parameters)
{
  dout(10) << "technique=" << technique << dendl;
  map<string, string>::const_iterator parameter;
  parameter = parameters.find("ruleset-root");
  if (parameter != parameters.end())
    ruleset_root = parameter->second;
  parameter = parameters.find("ruleset-failure-domain");
  if (parameter != parameters.end())
    ruleset_failure_domain = parameter->second;
  parse(parameters);
  prepare();
}

// -----------------------------------------------------------------------------

unsigned int
ErasureCodeIntelIsa::get_chunk_size(unsigned int object_size) const
{
  unsigned alignment = get_alignment();
  unsigned tail = object_size % alignment;
  unsigned padded_length = object_size + (tail ? (alignment - tail) : 0);
  assert(padded_length % k == 0);
  return padded_length / k;
}

// -----------------------------------------------------------------------------

int
ErasureCodeIntelIsa::minimum_to_decode(const set<int> &want_to_read,
                                       const set<int> &available_chunks,
                                       set<int> *minimum)
{
  if (includes(available_chunks.begin(), available_chunks.end(),
               want_to_read.begin(), want_to_read.end())) {
    *minimum = want_to_read;
  } else {
    if (available_chunks.size() < (unsigned) k)
      return -EIO;
    set<int>::iterator i;
    unsigned j;
    for (i = available_chunks.begin(), j = 0; j < (unsigned) k; ++i, j++)
      minimum->insert(*i);
  }
  return 0;
}

// -----------------------------------------------------------------------------

int
ErasureCodeIntelIsa::minimum_to_decode_with_cost(const set<int> &want_to_read,
                                                 const map<int, int> &available,
                                                 set<int> *minimum)
{
  set <int> available_chunks;
  for (map<int, int>::const_iterator i = available.begin();
       i != available.end();
       ++i)
    available_chunks.insert(i->first);
  return minimum_to_decode(want_to_read, available_chunks, minimum);
}

// -----------------------------------------------------------------------------

int
ErasureCodeIntelIsa::encode(const set<int> &want_to_encode,
                            const bufferlist &in,
                            map<int, bufferlist> *encoded)
{
  unsigned blocksize = get_chunk_size(in.length());
  unsigned padded_length = blocksize * k;
  dout(10) << "encode adjusted buffer length from " << in.length()
    << " to " << padded_length << dendl;
  assert(padded_length % k == 0);
  bufferlist out(in);

  if (padded_length - in.length() > 0) {
    bufferptr pad(padded_length - in.length());
    pad.zero();
    out.push_back(pad);
  }
  unsigned coding_length = blocksize * m;
  bufferptr coding(buffer::create_page_aligned(coding_length));
  out.push_back(coding);
  out.rebuild_page_aligned();
  char *chunks[k + m];

  for (int i = 0; i < k + m; i++) {
    bufferlist &chunk = (*encoded)[i];
    chunk.substr_of(out, i * blocksize, blocksize);
    chunks[i] = chunk.c_str();
  }

  isa_encode(&chunks[0], &chunks[k], blocksize);

  for (int i = 0; i < k + m; i++) {
    if (want_to_encode.count(i) == 0)
      encoded->erase(i);
  }
  return 0;
}

// -----------------------------------------------------------------------------

int
ErasureCodeIntelIsa::decode(const set<int> &want_to_read,
                            const map<int, bufferlist> &chunks,
                            map<int, bufferlist> *decoded)
{
  vector<int> have;
  have.reserve(chunks.size());

  for (map<int, bufferlist>::const_iterator i = chunks.begin();
       i != chunks.end();
       ++i) {
    have.push_back(i->first);
  }

  if (includes(
               have.begin(),
               have.end(),
               want_to_read.begin(),
               want_to_read.end())) {
    for (set<int>::iterator i = want_to_read.begin();
         i != want_to_read.end();
         ++i) {
      (*decoded)[*i] = chunks.find(*i)->second;
    }
    return 0;
  }
  unsigned blocksize = (*chunks.begin()).second.length();
  int erasures[k + m + 1];
  int erasures_count = 0;
  char *data[k];
  char *coding[m];

  bool only_source_failures = true;

  for (int i = 0; i < k + m; i++) {
    if (chunks.find(i) == chunks.end()) {
      erasures[erasures_count] = i;
      erasures_count++;
      bufferptr ptr(buffer::create_page_aligned(blocksize));
      (*decoded)[i].push_front(ptr);
      if (i >= k)
        only_source_failures = false;
    } else {
      (*decoded)[i] = chunks.find(i)->second;
      (*decoded)[i].rebuild_page_aligned();
    }
    if (i < k) {
      data[i] = (*decoded)[i].c_str();
    } else {
      coding[i - k] = (*decoded)[i].c_str();
    }
  }
  erasures[erasures_count] = -1;

  if (erasures_count > 0) {
    int retc = isa_decode(erasures, data, coding, blocksize);
    if (only_source_failures || retc) {
      return retc;
    } else {
      // missing coding chunks need a full re-encoding
      isa_encode(data, coding, blocksize);
      return 0;
    }
  } else
    return 0;
}

// -----------------------------------------------------------------------------

int
ErasureCodeIntelIsa::to_int(const std::string &name,
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

// -----------------------------------------------------------------------------

void
ErasureCodeIntelIsaDefault::isa_encode(char **data,
                                       char **coding,
                                       int blocksize)
{
  (Isa_EcEncodeData) (blocksize, k, m, g_encode_tbls,
    (unsigned char**) data, (unsigned char**) coding);
}

// -----------------------------------------------------------------------------

bool
ErasureCodeIntelIsaDefault::erasure_contains(int *erasures, int i)
{
  for (int l = 0; erasures[l] != -1; l++) {
    if (erasures[l] == i)
      return true;
  }
  return false;
}

// -----------------------------------------------------------------------------

int
ErasureCodeIntelIsaDefault::isa_decode(int *erasures,
                                       char **data,
                                       char **coding,
                                       int blocksize)
{
  int nerrs = 0;
  int i, j, r, s;

  // count the errors 
  for (int l = 0; erasures[l] != -1; l++) {
    nerrs++;
  }

  unsigned char *recover_source[k];
  unsigned char *recover_target[m];

  memset(recover_source, 0, sizeof (recover_source));
  memset(recover_target, 0, sizeof (recover_target));

  unsigned char b[k * (m + k)];
  unsigned char c[k * (m + k)];
  unsigned char d[k * (m + k)];
  unsigned char g_decode_tbls[k * (m + k)*32];

  if (nerrs > m)
    return -1;

  // Construct b by removing error rows
  for (i = 0, r = 0; i < k; i++, r++) {
    while (erasure_contains(erasures, r))
      r++;
    for (j = 0; j < k; j++)
      b[k * i + j] = a[k * r + j];
  }

  // Compute inverted matrix
  if ((*Isa_GfInvertMatrix)(b, d, k) < 0) {
    dout(0) << "isa_decode: bad matrix" << dendl;
    return -1;
  }

  // Assign source and target buffers
  for (i = 0, s = 0, r = 0; ((r < k) || (s < nerrs) || (i < (k + m))); i++) {
    if (!erasure_contains(erasures, i)) {
      if (i < k) {
        recover_source[r] = (unsigned char*) data[i];
      } else {
        recover_source[r] = (unsigned char*) coding[i - k];
      }
      r++;
    } else {
      if (i < k) {
        recover_target[s] = (unsigned char*) data[i];
      } else {
        // Note: decoding can not reconstruct a coding chunk, 
        // however for symmetry we assign the target buffer here
        recover_target[s] = (unsigned char*) coding[i - k];
      }
      s++;
    }
  }

  for (i = 0; i < nerrs; i++) {
    for (j = 0; j < k; j++) {
      c[k * i + j] = d[k * erasures[i] + j];
    }
  }

  // Initialize Decoding Table
  (*Isa_EcInitTables)(k, nerrs, c, g_decode_tbls);

  // Recover data sources
  (*Isa_EcEncodeData)(blocksize,
    k, nerrs, g_decode_tbls, recover_source, recover_target);

  return 0;

}

// -----------------------------------------------------------------------------

unsigned
ErasureCodeIntelIsaDefault::get_alignment() const
{
  return k * 64;
}

// -----------------------------------------------------------------------------

void
ErasureCodeIntelIsaDefault::parse(const map<std::string,
                                  std::string> &parameters)
{
  k = to_int("k", parameters, DEFAULT_K);
  m = to_int("m", parameters, DEFAULT_M);

  std::string isa_lib = "";

  if (parameters.find("intel-isa-lib") != parameters.end()) {
    isa_lib = parameters.find("intel-isa-lib")->second;
  } else {
    isa_lib = "isa-l.so";
  }

  // load ISA library only once
  IsaLibraryMutex.Lock();
  if (!IsaLibrary) {
    IsaLibrary = dlopen(isa_lib.c_str(), RTLD_LAZY);
  }
  IsaLibraryMutex.Unlock();
  
  if (!IsaLibrary) {
    derr << "unable to open isa-library " << isa_lib << dendl;
  } else {
    Isa_GenRsMatrix =
      (void (*)(unsigned char*, int, int))dlsym(IsaLibrary,
                                                "gf_gen_rs_matrix");
    Isa_GfInvertMatrix =
      (int (*)(unsigned char *, unsigned char *, int))dlsym(IsaLibrary,
                                                            "gf_invert_matrix");
    Isa_EcInitTables =
      (void (*)(int, int, unsigned char*, unsigned char*))
      dlsym(IsaLibrary, "ec_init_tables");
    Isa_EcEncodeData =
      (void (*)(int, int, int, unsigned char*, unsigned char**, unsigned char**))
      dlsym(IsaLibrary, "ec_encode_data");

    assert(Isa_GenRsMatrix);
    assert(Isa_GfInvertMatrix);
    assert(Isa_EcInitTables);
    assert(Isa_EcEncodeData);
  }
  assert(IsaLibrary);
}

// -----------------------------------------------------------------------------

void
ErasureCodeIntelIsaDefault::prepare()
{
  a = (unsigned char*) malloc(k * (m + k));
  g_encode_tbls = (unsigned char*) malloc(k * (m + k)*32);

  // build encoding table which needs to be computed once for a configure (k,m)
  (*Isa_GenRsMatrix)(a, k + m, k);
  (*Isa_EcInitTables)(k, m, &a[k * k], g_encode_tbls);
}
// -----------------------------------------------------------------------------
