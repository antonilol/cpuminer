EXTRA_DIST		= nomacro.pl

bin_PROGRAMS	= minerd

minerd_SOURCES	= miner.h compat.h cpu-miner.c util.c sha2.c

if USE_ASM
if ARCH_x86
minerd_SOURCES += sha2-x86.S
endif
if ARCH_x86_64
minerd_SOURCES += sha2-x64.S
endif
if ARCH_ARM
minerd_SOURCES += sha2-arm.S
endif
if ARCH_PPC
minerd_SOURCES += sha2-ppc.S
endif
endif
minerd_LDFLAGS	= $(PTHREAD_FLAGS)
minerd_LDADD	= @PTHREAD_LIBS@
minerd_CFLAGS	= -fno-strict-aliasing
minerd_CPPFLAGS	= $(PTHREAD_FLAGS)

