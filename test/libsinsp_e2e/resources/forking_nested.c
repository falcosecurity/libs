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

void* callback(void* arg) {
	return NULL;
}

int main() {
	int ctid;
	int cctid, cctid1, cctid2, cctid3, cctid4, cctid5;

	ctid = fork();

	if(ctid == 0) {
		//
		// CHILD PROCESS
		//
		printf("*1\n");
		pthread_t thread;
		pthread_create(&thread, NULL, callback, NULL);

		usleep(100000);
		cctid = fork();

		if(cctid == 0) {
			//
			// CHILD PROCESS
			//
			printf("*2\n");
			pthread_t thread;
			pthread_create(&thread, NULL, callback, NULL);

			usleep(100000);
			cctid1 = fork();

			if(cctid1 == 0) {
				//
				// CHILD PROCESS
				//
				printf("*3\n");
				pthread_t thread;
				pthread_create(&thread, NULL, callback, NULL);

				usleep(100000);
				cctid2 = fork();

				if(cctid2 == 0) {
					//
					// CHILD PROCESS
					//
					printf("*4\n");
					pthread_t thread;
					pthread_create(&thread, NULL, callback, NULL);

					usleep(100000);
					cctid3 = fork();

					if(cctid3 == 0) {
						printf("*5\n");
						//
						// CHILD PROCESS
						//
						pthread_t thread;
						pthread_create(&thread, NULL, callback, NULL);

						usleep(100000);
						cctid4 = fork();

						if(cctid4 == 0) {
							printf("*6\n");
							//
							// CHILD PROCESS
							//
							pthread_t thread;
							pthread_create(&thread, NULL, callback, NULL);

							usleep(100000);
							cctid5 = fork();

							if(cctid5 == 0) {
								printf("*7\n");
								return 0;
							} else {
								return 0;
							}
						} else {
							return 0;
						}
					} else {
						return 0;
					}
				} else {
					return 0;
				}
			} else {
				return 0;
			}
		} else {
			return 0;
		}
	} else {
		return 0;
	}
}
