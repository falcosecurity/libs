#!/bin/sh
# $Id: run.sh 3816 2020-02-08 15:00:18Z jkoshy $
#
# Run all the tests.

test_log=test.log

# setup cleanup trap
trap 'rm -rf /tmp/bsdar-*' 0 2 3 15

# load functions.
. ./func.sh

# global initialization.
init

exec 4>&1	# Save stdout for later use.

exec >${test_log} 2>&1
echo @TEST-RUN: `date`

# run tests.
for f in tc/*; do
    if [ -d $f ]; then
	. $f/`basename $f`.sh
    fi
done

# show statistics.
echo @RESULT: `statistic`

# Exit with an error code if any test had failed.
if grep 'not ok' ${test_log} >&4; then
	exit 1
fi
