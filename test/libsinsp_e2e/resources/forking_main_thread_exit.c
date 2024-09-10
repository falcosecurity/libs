// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

static int fd;

void* callback(void* arg) {
	char buf[1024];
	sleep(1);
	if(read(fd, buf, sizeof(buf)) < 0) {
		perror("read");
	}
	sleep(10);
	return NULL;
}

//
// This is outside the test files because gtest doesn't like
// pthread_exit() since it triggers an exception to unwind the stack
//
int main() {
	pthread_t thread;

	fd = open("/etc/passwd", O_RDONLY);
	if(fd == -1) {
		perror("open");
	}

	pthread_create(&thread, NULL, callback, NULL);
	pthread_exit(NULL);
}
