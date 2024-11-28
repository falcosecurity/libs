/**
 * 1. Erase archive symbol table's timestamp from ar archives,
 * make it easy to `diff'.  (option -e)
 * 2. Check the sanity of timestamp. (option -c)
 *
 * $Id: teraser.c 4025 2023-12-16 22:33:13Z jkoshy $
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define TSPOS	24		/* position of timestamp */
#define TSLEN	10		/* length of timstamp string */
#define BUFLEN	16		/* size of a temporary buffer */
#define TDELAY	3		/* max delay allowed */
#define COUNTER	"/tmp/bsdar-test-total"
#define PASSED	"/tmp/bsdar-test-passed"

#if BUFLEN < TSLEN
#error Temporary buffer size too small
#endif

static void	usage(void);

int
main(int argc, char **argv)
{
	int opt;
	char checktime;
	char erasetime;
	char buf[BUFLEN];
	char *tc;
	int fd;
	int ts;
	time_t now;
	FILE *ct, *ps;


	checktime = 0;
	erasetime = 0;
	tc = NULL;
	while ((opt = getopt(argc, argv, "cet:")) != -1) {
		switch(opt) {
		case 'c':
			checktime = 1;
			break;
		case 'e':
			erasetime = 1;
			break;
		case 't':
			tc = optarg;
			break;
		default:
			usage();
		}
	}

	argv += optind;
	if (*argv == NULL)
		usage();

	for (; *argv != NULL; argv++) {
		if (checktime) {
			if ((fd = open(*argv, O_RDONLY)) == -1) {
				fprintf(stderr,
				    "open %s failed(%s), skipping time check...\n,",
				    *argv, strerror(errno));
				goto ctend;
			}
			if ((lseek(fd, TSPOS, SEEK_SET)) == -1) {
				fprintf(stderr,
				    "lseek %s failed(%s), skipping...\n,",
				    *argv, strerror(errno));
				goto ctend;
			}
			if ((read(fd, buf, TSLEN)) != TSLEN) {
				fprintf(stderr,
				    "read %s failed(%s), skipping...\n,",
				    *argv, strerror(errno));
				goto ctend;
			}
			buf[TSLEN] = '\0';
			ts = atoi(buf);
			now = time(NULL);
			if (ts <= now && ts >= now - TDELAY) {
				fprintf(stderr, "%s - timestamp ok\n", tc);
				if ((ps = fopen(PASSED, "r")) != NULL) {
					if (fgets(buf, TSLEN, ps) != buf)
						perror("fgets");
					snprintf(buf, sizeof buf, "%d\n",
					    atoi(buf) + 1);
					fclose(ps);
				}
				if ((ps = fopen(PASSED, "w")) != NULL) {
					fputs(buf, ps);
					fclose(ps);
				}
			} else {
				fprintf(stderr, "%s - timestamp not ok\n", tc);
			}
			if ((ct = fopen(COUNTER, "r")) != NULL) {
				if (fgets(buf, TSLEN, ct) != NULL)
					perror("fgets");
				snprintf(buf, sizeof buf, "%d\n",
				    atoi(buf) + 1);
				fclose(ct);
			}
			if ((ct = fopen(COUNTER, "w")) != NULL) {
				fputs(buf, ct);
				fclose(ct);
			}

		ctend:
			close(fd);
		}

		if (erasetime) {
			if ((fd = open(*argv, O_RDWR)) == -1) {
				fprintf(stderr,
				    "open %s failed(%s), skipping time check...\n,",
				    *argv, strerror(errno));
				goto etend;
			}
			if ((lseek(fd, TSPOS, SEEK_SET)) == -1) {
				fprintf(stderr, "lseek %s failed(%s), skipping...,",
					*argv, strerror(errno));
				goto etend;
			}
			memset(buf, 32, TSLEN);
			if ((write(fd, buf, TSLEN)) != TSLEN)
				fprintf(stderr,
				    "read %s failed(%s), skipping...\n,",
				    *argv, strerror(errno));

		etend:
			close(fd);
		}
	}

	exit(EXIT_SUCCESS);
}

static void
usage(void)
{
	fprintf(stderr, "usage: teraser [-ce] [-t name] archive ...\n");
	exit(EXIT_FAILURE);
}
