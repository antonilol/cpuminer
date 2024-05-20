/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012-2017 pooler
 * Copyright 2022-2024 antonilol
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "cpuminer-config.h"
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#ifdef WIN32
#include <windows.h>
#else
#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#if HAVE_SYS_SYSCTL_H
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/sysctl.h>
#endif
#endif
#include "compat.h"
#include "miner.h"

#define PROGRAM_NAME		"minerd"
#define LP_SCANTIME		60

#ifdef __linux /* Linux specific policy and affinity management */
#include <sched.h>
static inline void drop_policy(void)
{
	struct sched_param param;
	param.sched_priority = 0;

#ifdef SCHED_IDLE
	if (unlikely(sched_setscheduler(0, SCHED_IDLE, &param) == -1))
#endif
#ifdef SCHED_BATCH
		sched_setscheduler(0, SCHED_BATCH, &param);
#endif
}

static inline void affine_to_cpu(int id, int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	sched_setaffinity(0, sizeof(set), &set);
}
#elif defined(__FreeBSD__) /* FreeBSD specific policy and affinity management */
#include <sys/cpuset.h>
static inline void drop_policy(void)
{
}

static inline void affine_to_cpu(int id, int cpu)
{
	cpuset_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, sizeof(cpuset_t), &set);
}
#else
static inline void drop_policy(void)
{
}

static inline void affine_to_cpu(int id, int cpu)
{
}
#endif

const uint32_t nonces = 16000000;
uint32_t blkheader[19];
uint32_t target[8] = {0};

struct thr_info *thr_info;
static int num_processors;

pthread_mutex_t applog_lock;
static pthread_mutex_t stats_lock;

static double *thr_hashrates;

static void *miner_thread(void *userdata)
{
	struct thr_info *mythr = userdata;
	int thr_id = mythr->id;
	uint32_t work[32] = {0};

	for (int i = 0; i < 19; i++) {
		work[i] = blkheader[i];
	}
	work[19] = 0xffffffffU / num_processors * thr_id;
	work[20] = 0x80000000;
	work[31] = 640;

	uint32_t end_nonce = 0xffffffffU / num_processors * (thr_id + 1);
	char s[16];
	int i;

	/* Set worker threads to nice 19 and then preferentially to SCHED_IDLE
	 * and if that fails, then SCHED_BATCH. No need for this to be an
	 * error if it fails */
	setpriority(PRIO_PROCESS, 0, 19);
	drop_policy();

	/* Cpu affinity only makes sense if the number of threads is a multiple
	 * of the number of CPUs */
	if (num_processors > 1) {
		affine_to_cpu(thr_id, thr_id);
	}

	while (work[19] < end_nonce) {
		unsigned long hashes_done;
		struct timeval tv_start, tv_end, diff;

		uint32_t step = end_nonce - work[19];
		if (step > nonces) {
			step = nonces;
		}

		hashes_done = 0;
		gettimeofday(&tv_start, NULL);

		/* scan nonces for a proof-of-work hash */
		if (scanhash_sha256d(thr_id, work, target, work[19] + step, &hashes_done)) {
			uint32_t h[20];
			for (uint8_t i = 0; i < 20; i++) {
				h[i] = swab32(work[i]);
			}
			char header_hex[161];
			bin2hex(header_hex, (unsigned char *) h, 80);
			header_hex[160]='\0';
			printf(header_hex);

			exit(0);
		}

		/* record scanhash elapsed time */
		gettimeofday(&tv_end, NULL);
		timeval_subtract(&diff, &tv_end, &tv_start);
		if (diff.tv_usec || diff.tv_sec) {
			pthread_mutex_lock(&stats_lock);
			thr_hashrates[thr_id] =
				hashes_done / (diff.tv_sec + 1e-6 * diff.tv_usec);
			pthread_mutex_unlock(&stats_lock);
		}
		if (thr_id == num_processors - 1) {
			double hashrate = 0.;
			for (i = 0; i < num_processors && thr_hashrates[i]; i++)
				hashrate += thr_hashrates[i];
			if (i == num_processors) {
				sprintf(s, hashrate >= 1e9 ? "%.0f" : "%.2f", 1e-6 * hashrate);
				fprintf(stderr, "   Hashrate: %s MH/s     \r", s);
			}
		}
	}

	applog(LOG_INFO, "Refreshing work                ");
	exit(0);

	return NULL;
}

static void show_version(void)
{
	fprintf(stderr, PACKAGE_STRING "\n built on " __DATE__ "\n features:"
#if defined(USE_ASM) && defined(__i386__)
		" i386"
#endif
#if defined(USE_ASM) && defined(__x86_64__)
		" x86_64"
		" PHE"
#endif
#if defined(USE_ASM) && (defined(__i386__) || defined(__x86_64__))
		" SSE2"
#endif
#if defined(__x86_64__) && defined(USE_AVX)
		" AVX"
#endif
#if defined(__x86_64__) && defined(USE_AVX2)
		" AVX2"
#endif
#if defined(__x86_64__) && defined(USE_XOP)
		" XOP"
#endif
#if defined(USE_ASM) && defined(__arm__) && defined(__APCS_32__)
		" ARM"
#if defined(__ARM_ARCH_5E__) || defined(__ARM_ARCH_5TE__) || \
	defined(__ARM_ARCH_5TEJ__) || defined(__ARM_ARCH_6__) || \
	defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || \
	defined(__ARM_ARCH_6M__) || defined(__ARM_ARCH_6T2__) || \
	defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__) || \
	defined(__ARM_ARCH_7__) || \
	defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || \
	defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7EM__)
		" ARMv5E"
#endif
#if defined(__ARM_NEON__)
		" NEON"
#endif
#endif
#if defined(USE_ASM) && (defined(__powerpc__) || defined(__ppc__) || defined(__PPC__))
		" PowerPC"
#if defined(__ALTIVEC__)
		" AltiVec"
#endif
#endif
		"\n");
}

#ifndef WIN32
static void signal_handler(int sig)
{
	switch (sig) {
	case SIGHUP:
		applog(LOG_INFO, "SIGHUP received");
		break;
	case SIGINT:
		applog(LOG_INFO, "SIGINT received, exiting");
		exit(0);
		break;
	case SIGTERM:
		applog(LOG_INFO, "SIGTERM received, exiting");
		exit(0);
		break;
	}
}
#endif

int main(int argc, char *argv[])
{
	if (argc > 2 && !strcmp(argv[2], "info")) {
		show_version();
	}

	if (argc < 2) {
		fprintf(stderr, "no blockheader argument\n");
		return 1;
	}

	if (strlen(argv[1]) != (80 - 4) * 2 && strlen(argv[1]) != 80 * 2) {
		fprintf(stderr, "invalid length\n");
		return 1;
	}

	for (int i = 0; i < 19; i++) {
		char n[9];
		memcpy(n, argv[1] + i * 8, 8);
		n[8] = '\0';
		blkheader[i] = strtoul(n, NULL, 16);
	}

	const uint32_t nCompact = swab32(blkheader[18]);
	// https://github.com/bitcoin/bitcoin/blob/fa99e108e778b5169b3de2ce557af68f1fe0ac0b/src/arith_uint256.cpp#L203-L221
	const int nSize = nCompact >> 24;
	const uint32_t nWord = nCompact & 0x007fffff;

	if (nWord != 0 && (nCompact & 0x00800000) != 0) {
		fprintf(stderr, "bits negative");
		return 1;
	}

	if (nWord != 0 && ((nSize > 34) || (nWord > 0xff && nSize > 33) || (nWord > 0xffff && nSize > 32))) {
		fprintf(stderr, "bits overflow");
		return 1;
	}

	memcpy((unsigned char *) target + nSize - 3, &nWord, 3);

	struct thr_info *thr;
	int i;

	pthread_mutex_init(&applog_lock, NULL);
	pthread_mutex_init(&stats_lock, NULL);

#if defined(WIN32)
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	num_processors = sysinfo.dwNumberOfProcessors;
#elif defined(_SC_NPROCESSORS_ONLN)
	num_processors = sysconf(_SC_NPROCESSORS_ONLN);
#elif defined(CTL_HW) && defined(HW_NCPU)
	int req[] = { CTL_HW, HW_NCPU };
	size_t len = sizeof(num_processors);
	sysctl(req, 2, &num_processors, &len, NULL, 0);
#else
	num_processors = 1;
#endif
	if (num_processors < 1)
		num_processors = 1;

	thr_info = calloc(num_processors + 3, sizeof(*thr));
	if (!thr_info)
		return 1;
	
	thr_hashrates = (double *) calloc(num_processors, sizeof(double));
	if (!thr_hashrates)
		return 1;

	/* start mining threads */
	for (i = 0; i < num_processors; i++) {
		thr = &thr_info[i];

		thr->id = i;
		thr->q = tq_new();
		if (!thr->q)
			return 1;

		if (unlikely(pthread_create(&thr->pth, NULL, miner_thread, thr))) {
			applog(LOG_ERR, "thread %d create failed", i);
			return 1;
		}
	}

	applog(LOG_INFO, "%d miner threads started", num_processors);

	/* main loop - simply wait for miner threads to exit */
	for (i = 0; i < num_processors; i++) {
		pthread_join(thr_info[i].pth, NULL);
	}

	return 0;
}
