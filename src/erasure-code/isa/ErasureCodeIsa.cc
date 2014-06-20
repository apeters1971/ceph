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
#include "ErasureCodeIsa.h"
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

// -----------------------------------------------------------------------------

static ostream&
_prefix(std::ostream* _dout)
{
  return *_dout << "ErasureCodeIsa: ";
}
// -----------------------------------------------------------------------------

int
ErasureCodeIsa::create_ruleset(const string &name,
                               CrushWrapper &crush,
                               ostream *ss) const
{
  return crush.add_simple_ruleset(name, ruleset_root, ruleset_failure_domain,
                                  "indep", pg_pool_t::TYPE_ERASURE, ss);
}

// -----------------------------------------------------------------------------

void
ErasureCodeIsa::init(const map<string, string> &parameters)
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
ErasureCodeIsa::get_chunk_size(unsigned int object_size) const
{
  unsigned alignment = get_alignment();
  unsigned tail = object_size % alignment;
  unsigned padded_length = object_size + (tail ? (alignment - tail) : 0);
  assert(padded_length % k == 0);
  return padded_length / k;
}

// -----------------------------------------------------------------------------

int
ErasureCodeIsa::minimum_to_decode(const set<int> &want_to_read,
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
ErasureCodeIsa::minimum_to_decode_with_cost(const set<int> &want_to_read,
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
ErasureCodeIsa::encode(const set<int> &want_to_encode,
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
ErasureCodeIsa::decode(const set<int> &want_to_read,
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

  for (int i = 0; i < k + m; i++) {
    if (chunks.find(i) == chunks.end()) {
      erasures[erasures_count] = i;
      erasures_count++;
      bufferptr ptr(buffer::create_page_aligned(blocksize));
      (*decoded)[i].push_front(ptr);
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
    return retc;
  } else
    return 0;
}

// -----------------------------------------------------------------------------

int
ErasureCodeIsa::to_int(const std::string &name,
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
ErasureCodeIsaDefault::isa_encode(char **data,
                                  char **coding,
                                  int blocksize)
{
  ec_encode_data(blocksize, k, m, g_encode_tbls,
                 (unsigned char**) data, (unsigned char**) coding);
}

// -----------------------------------------------------------------------------

bool
ErasureCodeIsaDefault::erasure_contains(int *erasures, int i)
{
  for (int l = 0; erasures[l] != -1; l++) {
    if (erasures[l] == i)
      return true;
  }
  return false;
}

// -----------------------------------------------------------------------------

int
ErasureCodeIsaDefault::isa_decode(int *erasures,
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
  if (gf_invert_matrix(b, d, k) < 0) {
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
        recover_target[s] = (unsigned char*) coding[i - k];
      }
      s++;
    }
  }

  for (int p = 0; p < nerrs; p++) {
    if (erasures[p] < k) {
      // decoding matrix elements for data chunks
      for (j = 0; j < k; j++) {
        c[k * p + j] = d[k * erasures[p] + j];
      }
    } else {
      int s = 0;
      // decoding matrix element for coding chunks
      for (i = 0; i < k; i++) {
        s = 0;
        for (j = 0; j < k; j++)
          s ^= gf_mul(d[j * k + i],
                      a[k * erasures[p] + j]);

        c[k * p + i] = s;
      }
    }
  }

  // Initialize Decoding Table
  ec_init_tables(k, nerrs, c, g_decode_tbls);

  // Recover data sources
  ec_encode_data(blocksize,
                 k, nerrs, g_decode_tbls, recover_source, recover_target);

  return 0;

}

// -----------------------------------------------------------------------------

unsigned
ErasureCodeIsaDefault::get_alignment() const
{
  return k * 64;
}

// -----------------------------------------------------------------------------

void
ErasureCodeIsaDefault::parse(const map<std::string,
                             std::string> &parameters)
{
  k = to_int("k", parameters, DEFAULT_K);
  m = to_int("m", parameters, DEFAULT_M);
}

// -----------------------------------------------------------------------------

void
ErasureCodeIsaDefault::prepare()
{
  a = (unsigned char*) malloc(k * (m + k));
  g_encode_tbls = (unsigned char*) malloc(k * (m + k)*32);

  // build encoding table which needs to be computed once for a configure (k,m)
  assert((matrixtype == kVandermonde) || (matrixtype == kCauchy));
  if (matrixtype == kVandermonde)
    gf_gen_rs_matrix(a, k + m, k);
  if (matrixtype == kCauchy)
    gf_gen_cauchy1_matrix(a, k + m, k);

  ec_init_tables(k, m, &a[k * k], g_encode_tbls);
}
// -----------------------------------------------------------------------------
