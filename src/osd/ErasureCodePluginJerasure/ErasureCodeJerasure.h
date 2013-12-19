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

#ifndef CEPH_ERASURE_CODE_JERASURE_H
#define CEPH_ERASURE_CODE_JERASURE_H

#include "osd/ErasureCodeInterface.h"
#include <dlfcn.h>

class ErasureCodeJerasure : public ErasureCodeInterface {
public:
  int k;
  int m;
  int w;
  const char *technique;

  int lp; // # of local parities to compute
  static const int DEFAULT_LOCAL_PARITY = 0;
  
  ErasureCodeJerasure(const char *_technique) :
    technique(_technique) , lp(0)
  {}

  virtual ~ErasureCodeJerasure() {}
  
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

  void init(const map<std::string,std::string> &parameters);
  virtual void jerasure_encode(char **data,
                               char **coding,
                               int blocksize) = 0;
  virtual int jerasure_decode(int *erasures,
                               char **data,
                               char **coding,
                               int blocksize) = 0;
  virtual unsigned get_alignment() = 0;
  virtual void parse(const map<std::string,std::string> &parameters) = 0;
  virtual void prepare() = 0;
  static int to_int(const std::string &name,
                    const map<std::string,std::string> &parameters,
                    int default_value);
  static bool is_prime(int value);
};

class ErasureCodeJerasureReedSolomonVandermonde : public ErasureCodeJerasure {
public:
  static const int DEFAULT_K = 7;
  static const int DEFAULT_M = 3;
  static const int DEFAULT_W = 8;
  int *matrix;

  ErasureCodeJerasureReedSolomonVandermonde() :
    ErasureCodeJerasure("reed_sol_van"),
    matrix(0)
  { }
  virtual ~ErasureCodeJerasureReedSolomonVandermonde() {
    if (matrix)
      free(matrix);
  }

  virtual void jerasure_encode(char **data,
                               char **coding,
                               int blocksize);
  virtual int jerasure_decode(int *erasures,
                               char **data,
                               char **coding,
                               int blocksize);
  virtual unsigned get_alignment();
  virtual void parse(const map<std::string,std::string> &parameters);
  virtual void prepare();
};

class ErasureCodeJerasureReedSolomonRAID6 : public ErasureCodeJerasure {
public:
  static const int DEFAULT_K = 7;
  static const int DEFAULT_W = 8;
  int *matrix;

  ErasureCodeJerasureReedSolomonRAID6() :
    ErasureCodeJerasure("reed_sol_r6_op"),
    matrix(0)
  { }
  virtual ~ErasureCodeJerasureReedSolomonRAID6() {
    if (matrix)
      free(matrix);
  }

  virtual void jerasure_encode(char **data,
                               char **coding,
                               int blocksize);
  virtual int jerasure_decode(int *erasures,
                               char **data,
                               char **coding,
                               int blocksize);
  virtual unsigned get_alignment();
  virtual void parse(const map<std::string,std::string> &parameters);
  virtual void prepare();
};

class ErasureCodeJerasureCauchy : public ErasureCodeJerasure {
public:
  static const int DEFAULT_K = 7;
  static const int DEFAULT_M = 3;
  static const int DEFAULT_W = 8;
  static const int DEFAULT_PACKETSIZE = 8;
  int *bitmatrix;
  int **schedule;
  int packetsize;

  ErasureCodeJerasureCauchy(const char *technique) :
    ErasureCodeJerasure(technique),
    bitmatrix(0),
    schedule(0)
  { }
  virtual ~ErasureCodeJerasureCauchy() {
    if (bitmatrix)
      free(bitmatrix);
    if (schedule)
      free(schedule);
  }

  virtual void jerasure_encode(char **data,
                               char **coding,
                               int blocksize);
  virtual int jerasure_decode(int *erasures,
                               char **data,
                               char **coding,
                               int blocksize);
  virtual unsigned get_alignment();
  virtual void parse(const map<std::string,std::string> &parameters);
  void prepare_schedule(int *matrix);
};

class ErasureCodeJerasureCauchyOrig : public ErasureCodeJerasureCauchy {
public:
  ErasureCodeJerasureCauchyOrig() :
    ErasureCodeJerasureCauchy("cauchy_orig")
  {}

  virtual void prepare();
};

class ErasureCodeJerasureCauchyGood : public ErasureCodeJerasureCauchy {
public:
  ErasureCodeJerasureCauchyGood() :
    ErasureCodeJerasureCauchy("cauchy_good")
  {}

  virtual void prepare();
};

class ErasureCodeJerasureLiberation : public ErasureCodeJerasure {
public:
  static const int DEFAULT_K = 2;
  static const int DEFAULT_M = 2;
  static const int DEFAULT_W = 7;
  static const int DEFAULT_PACKETSIZE = 8;
  int *bitmatrix;
  int **schedule;
  int packetsize;

  ErasureCodeJerasureLiberation(const char *technique = "liberation") :
    ErasureCodeJerasure(technique),
    bitmatrix(0),
    schedule(0)
  { }
  virtual ~ErasureCodeJerasureLiberation();

  virtual void jerasure_encode(char **data,
                               char **coding,
                               int blocksize);
  virtual int jerasure_decode(int *erasures,
                               char **data,
                               char **coding,
                               int blocksize);
  virtual unsigned get_alignment();
  virtual void parse(const map<std::string,std::string> &parameters);
  virtual void prepare();
};

class ErasureCodeJerasureBlaumRoth : public ErasureCodeJerasureLiberation {
public:
  ErasureCodeJerasureBlaumRoth() :
    ErasureCodeJerasureLiberation("blaum_roth")
  {}

  virtual void prepare();
};

class ErasureCodeJerasureLiber8tion : public ErasureCodeJerasureLiberation {
public:
  static const int DEFAULT_K = 2;
  static const int DEFAULT_M = 2;
  static const int DEFAULT_W = 8;

  ErasureCodeJerasureLiber8tion() :
    ErasureCodeJerasureLiberation("liber8tion")
  {}

  virtual void parse(const map<std::string,std::string> &parameters);
  virtual void prepare();
};

class ErasureCodeIntelIsa : public ErasureCodeJerasure {
public:
  static const int DEFAULT_K = 2;
  static const int DEFAULT_M = 2;
  void* IsaLibrary;
  void (*Isa_GenRsMatrix)(unsigned char *a, int mk, int k);
  int  (*Isa_GfInvertMatrix)(unsigned char *in, unsigned char *out, int k);
  void (*Isa_EcInitTables)(int k, int rows, unsigned char* a, 
			  unsigned char* g_tbls);
  void (*Isa_EcEncodeData)(int len, int k, int rows, unsigned char *g_tbls, unsigned char **data, unsigned char **coding);

  unsigned char a[96*64]; // 96 = Max(M+K), 64 = Max(k);
  unsigned char b[96*64]; // 96 = Max(M+K), 64 = Max(k);
  unsigned char c[96*64]; // 96 = Max(M+K), 64 = Max(k);
  unsigned char d[96*64]; // 96 = Max(M+K), 64 = Max(k);
  unsigned char g_tbls[64*64*32]; // 64 ~ max allowed value of k

  bool erasure_contains(int *erasures,int i);

  ErasureCodeIntelIsa() :
    ErasureCodeJerasure("isa-l"),IsaLibrary(0), Isa_GenRsMatrix(0), Isa_EcInitTables(0), Isa_EcEncodeData(0)
  {}
    
  virtual ~ErasureCodeIntelIsa() {
    if (IsaLibrary)
      dlclose(IsaLibrary);
  }
  
  virtual unsigned get_alignment();
  virtual void parse(const map<std::string,std::string> &parameters);
  virtual void prepare();

  virtual void jerasure_encode(char **data,
                               char **coding,
                               int blocksize);

  virtual int jerasure_decode(int *erasures,
			      char **data,
			      char **coding,
			      int blocksize);
};

#endif
