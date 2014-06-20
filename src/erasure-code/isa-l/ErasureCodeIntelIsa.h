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

/**
 * @file   ErasureCodeIntelIsa.cc
 *
 * @brief  Erasure Code CODEC using the INTEL ISA-L library.
 * 
 * The factory plug-in class allows to call individual encoding techniques.
 * The INTEL ISA-L library supports one encoding scheme (reed_sol_van = default)
 * 
 * The plug-in can be compiled without having the INTEL ISA library installed. 
 * The ISA library is loaded with dlopen at runtime. 
 */

#ifndef CEPH_ERASURE_CODE_INTEL_ISA_L_H
#define CEPH_ERASURE_CODE_INTEL_ISA_L_H

// -----------------------------------------------------------------------------
#include "common/Mutex.h"
#include "erasure-code/ErasureCodeInterface.h"
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------

class ErasureCodeIntelIsa : public ErasureCodeInterface {
public:
  int k;
  int m;
  int w;
  const char *technique;
  string ruleset_root;
  string ruleset_failure_domain;

  ErasureCodeIntelIsa(const char *_technique) :
  technique(_technique),
  ruleset_root("default"),
  ruleset_failure_domain("host")
  {
  }

  virtual
  ~ErasureCodeIntelIsa()
  {
  }

  virtual int create_ruleset(const string &name,
                             CrushWrapper &crush,
                             ostream *ss) const;

  virtual unsigned int 
  get_chunk_count() const
  {
    return k + m;
  }

  virtual unsigned int
  get_data_chunk_count() const
  {
    return k;
  }

  virtual unsigned int get_chunk_size(unsigned int object_size) const;

  virtual int minimum_to_decode(const set<int> &want_to_read,
                                const set<int> &available_chunks,
                                set<int> *minimum);

  virtual int minimum_to_decode_with_cost(const set<int> &want_to_read,
                                          const map<int, int> &available,
                                          set<int> *minimum);

  virtual int encode(const set<int> &want_to_encode,
                     const bufferlist &in,
                     map<int, bufferlist> *encoded);

  virtual int decode(const set<int> &want_to_read,
                     const map<int, bufferlist> &chunks,
                     map<int, bufferlist> *decoded);

  void init(const map<std::string, std::string> &parameters);
  
  virtual void isa_encode(char **data,
                          char **coding,
                          int blocksize) = 0;


  virtual int isa_decode(int *erasures,
                         char **data,
                         char **coding,
                         int blocksize) = 0;

  virtual unsigned get_alignment() const = 0;

  virtual void parse(const map<std::string, std::string> &parameters) = 0;

  virtual void prepare() = 0;

  static int to_int(const std::string &name,
                    const map<std::string, std::string> &parameters,
                    int default_value);
};

// -----------------------------------------------------------------------------

class ErasureCodeIntelIsaDefault : public ErasureCodeIntelIsa {
public:
  static const int DEFAULT_K = 7;
  static const int DEFAULT_M = 3;

  
  static Mutex IsaLibraryMutex;
  
  static void* IsaLibrary;

  void (*Isa_GenRsMatrix)(unsigned char *a, int mk, int k);

  int (*Isa_GfInvertMatrix)(unsigned char *in, unsigned char *out, int k);

  void (*Isa_EcInitTables)(int k, int rows, unsigned char* a,
                           unsigned char* g_tbls);

  void (*Isa_EcEncodeData)(int len, int k, int rows,
                           unsigned char *g_tbls, unsigned char **data,
                           unsigned char **coding);

  unsigned char* a; // encoding coefficient
  unsigned char* g_encode_tbls; // encoding table

  ErasureCodeIntelIsaDefault() : ErasureCodeIntelIsa("default"),
  a(0), g_encode_tbls(0)
  {
  }

  virtual
  ~ErasureCodeIntelIsaDefault()
  {
    if (a) {
      free(a);
    }
    if (g_encode_tbls) {
      free(g_encode_tbls);
    }
  }

  virtual void isa_encode(char **data,
                          char **coding,
                          int blocksize);

  virtual bool erasure_contains(int *erasures, int i);

  virtual int isa_decode(int *erasures,
                         char **data,
                         char **coding,
                         int blocksize);

  virtual unsigned get_alignment() const;
  
  virtual void parse(const map<std::string, std::string> &parameters);
  
  virtual void prepare();
};

#endif
