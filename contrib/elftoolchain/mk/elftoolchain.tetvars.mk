#
# Configuration information for TET.
#
# $Id: elftoolchain.tetvars.mk 4035 2024-01-16 17:46:07Z jkoshy $
#

.if !defined(TOP)
.error Make variable \"TOP\" has not been defined.
.endif

# Set TET_ROOT and version.
TET_VERSION?=		3.8
TET_ROOT?=		${TOP}/tests/tet/tet/tet${TET_VERSION}

TET_DOWNLOAD_URL=	\
	http://tetworks.opengroup.org/downloads/38/software/Sources/${TET_VERSION}/tet${TET_VERSION}-src.tar.gz

# The directory where test journals are placed.
TET_RESULTS_DIR?=	results

# The temporary directory used by TET.
TET_TMP_DIR?=		tet_tmp_dir
