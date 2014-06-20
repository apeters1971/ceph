# ISA
noinst_HEADERS += \
  erasure-code/isa-l/isa-l/include/erasure_code.h

isa_sources = \
  erasure-code/isa-l/ErasureCodeIntelIsa.cc \
  erasure-code/isa-l/ErasureCodePluginIntelIsa.cc

libec_intel_isal_la_SOURCES = ${isa_sources}

libec_intel_isal_la_LIBADD = $(LIBCRUSH) $(PTHREAD_LIBS) $(EXTRALIBS)
libec_intel_isal_la_LDFLAGS = ${AM_LDFLAGS} -version-info 2:10:0
if LINUX
libec_intel_isal_la_LDFLAGS += -export-symbols-regex '.*__erasure_code_.*'
endif

erasure_codelib_LTLIBRARIES += libec_intel_isal.la

