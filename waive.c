/*
 * this file is part of libwaive.
 *
 * Copyright (c) 2015 Dima Krasner
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <sys/socket.h>
#include <sys/mman.h>
#include <errno.h>
#include <stddef.h>

#include <seccomp.h>

#include "waive.h"

int waive(const int flags)
{
	scmp_filter_ctx ctx;
	int ret = -1;

	ctx = seccomp_init(SCMP_ACT_ALLOW);
	if (NULL == ctx)
		goto out;

	if (0 != (WAIVE_INET & flags)) {
		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(socket),
		                          1,
		                          SCMP_A0(SCMP_CMP_EQ, AF_INET)))
			goto release;

		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(socket),
		                          1,
		                          SCMP_A0(SCMP_CMP_EQ, AF_INET6)))
			goto release;

		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(socketpair),
		                          1,
		                          SCMP_A0(SCMP_CMP_EQ, AF_INET)))
			goto release;

		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(socketpair),
		                          1,
		                          SCMP_A0(SCMP_CMP_EQ, AF_INET6)))
			goto release;
	}

	if (0 != (WAIVE_UN & flags)) {
		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(socket),
		                          1,
		                          SCMP_A0(SCMP_CMP_EQ, AF_UNIX)))
			goto release;

		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(socketpair),
		                          1,
		                          SCMP_A0(SCMP_CMP_EQ, AF_UNIX)))
			goto release;
	}

	if (0 != (WAIVE_PACKET & flags)) {
		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(socket),
		                          1,
		                          SCMP_A0(SCMP_CMP_EQ, AF_PACKET)))
			goto release;

		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(socketpair),
		                          1,
		                          SCMP_A0(SCMP_CMP_EQ, AF_PACKET)))
			goto release;
	}

	if (0 != (WAIVE_MOUNT & flags)) {
		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(mount),
		                          0))
			goto release;

		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(umount),
		                          0))
			goto release;

		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(umount2),
		                          0))
			goto release;
	}

	if (0 != (WAIVE_OPEN & flags)) {
		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(open),
		                          0))
			goto release;

		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(openat),
		                          0))
			goto release;

		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(creat),
		                          0))
			goto release;
	}

	if (0 != (WAIVE_EXEC & flags)) {
		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(execve),
		                          0))
			goto release;

		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(mprotect),
		                          1,
		                          SCMP_A2(SCMP_CMP_EQ, PROT_EXEC)))
			goto release;

		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(mprotect),
		                          1,
		                          SCMP_A2(SCMP_CMP_EQ, PROT_READ | PROT_EXEC)))
			goto release;

		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(mprotect),
		                          1,
		                          SCMP_A2(SCMP_CMP_EQ, PROT_WRITE | PROT_EXEC)))
			goto release;

		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(mprotect),
		                          1,
		                          SCMP_A2(SCMP_CMP_EQ,
		                                  PROT_READ | PROT_WRITE | PROT_EXEC)))
			goto release;

		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(mmap),
		                          1,
		                          SCMP_A2(SCMP_CMP_EQ, PROT_READ | PROT_EXEC)))
			goto release;

		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(mmap),
		                          1,
		                          SCMP_A2(SCMP_CMP_EQ, PROT_WRITE | PROT_EXEC)))
			goto release;

		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(mmap),
		                          1,
		                          SCMP_A2(SCMP_CMP_EQ,
		                                  PROT_READ | PROT_WRITE | PROT_EXEC)))
			goto release;
	}

	if (0 != (WAIVE_CLONE & flags)) {
		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(clone),
		                          0))
			goto release;
	}

	if (0 != (WAIVE_KILL & flags)) {
		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(kill),
		                          1,
		                          SCMP_A0(SCMP_CMP_NE, 0)))
			goto release;
	}

	if (0 != (WAIVE_PIPE & flags)) {
		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(pipe),
		                          0))
			goto release;

		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(pipe2),
		                          0))
			goto release;

		if (0 != seccomp_rule_add(ctx,
		                          SCMP_ACT_ERRNO(EPERM),
		                          SCMP_SYS(mknod),
		                          0))
			goto release;
	}

	if (0 == seccomp_load(ctx))
		ret = 0;

release:
	seccomp_release(ctx);

out:
	return ret;
}
