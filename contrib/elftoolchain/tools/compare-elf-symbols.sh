#!/bin/sh
#
# Compare symbols in sys/${arch}/include/*.h with the corresponding
# symbols in Elftoolchain's common/sys/elfconstants.m4.
#
# $Id$

usage() {
  if [ ${#} -gt 0 ]; then
      echo "$@"
      echo
  fi

  echo "Usage: $0 [options]"
  echo
  echo 'Compare OS ELF symbol definitions against Elftoolchain sources.'
  echo
  echo 'Options:'
  echo '  -a ARCH_DIR        The architecture directory to check.'
  echo '  -e ELF_CONSTANTS   The <elfconstants.m4> file to check against.'
  echo "                     Default: ${default_elfconstants_file}."
  echo '  -o OS_FLAVOR       Source tree flavor: one of FreeBSD or NetBSD.'
  echo "                     Default: ${default_os_flavor}."
  echo '  -t SYMBOL_TYPE     Type of ELF symbol to compare.'
  echo "                     Default: ${default_symbol_type}."
}

#
# Set defaults.
#
if ! type realpath > /dev/null; then
   echo "ERROR: No 'realpath' utility found."
   exit 72			# EX_OSFILE
fi

script_location="$(realpath $0)"
script_dir="$(dirname ${script_location})"
default_elfconstants_file="${script_dir}/../common/sys/elfconstants.m4"
default_os_flavor=NetBSD
default_symbol_type=R		# Relocations.

#
# Helper functions.
#

# get_arch_name(arch-dir)
#
# Translate a directory under 'sys/arch' to an architecture name.
get_arch_name() {
    echo "$(basename $1)"
}

# get_relocation_prefix(arch-name)
#
# Translate an architecture name to an R_* symbol prefix.
get_relocation_prefix() {
    case "${1}" in
	i386)
	    echo R_386_
	    ;;
	ia64)
	    case ${os_flavor} in
		FreeBSD)
		    echo R_IA_64_
		    ;;
		NetBSD)
		    echo R_IA64_
		    ;;
	    esac
	    ;;
	*)
	    echo "Unsupported architecture '${1}'."
	    exit 65		# EX_DATAERR
	    ;;
    esac
}

# get_os_symbols(symbol-prefix)
#
# Extract symbols matching the specified prefix from OS headers.
get_os_symbols() {
    find . -name '*.h' | \
	xargs egrep -E "#define[[:space:]]+${1}" | \
	awk '{ printf("_(%s,\t%s)\n", $2, $3); }'
}

# get_elf_constants(prefix)
#
# Extract symbols matching the specified prefix from <elfconstants.m4>.
get_elf_constants() {
    awk -v prefix=$1 '$1 ~ prefix { print }' ${elf_constants_file}
}

#
# Parse options.
#
options=":a:e:o:t:"
while getopts "$options" var; do
  case $var in
  a) arch_dir="${OPTARG}"
     ;;
  e) elf_constants_file="$OPTARG"
     ;;
  o) os_flavor="${OPTARG}"
     ;;
  t) symbol_type="${OPTARG}"
     ;;
  '?') usage "ERROR: Unknown option: '-$OPTARG'."
       exit 64			# EX_USAGE
       ;;
  ':') usage "ERROR: Option '-$OPTARG' expects an argument."
       exit 64			# EX_USAGE
       ;;
  esac
  shift $((OPTIND - 1))
done

# Sanity check arguments.
if [ -z "${arch_dir}" ]; then
    echo "ERROR: Option '-a' must be specified."
    exit 64			# EX_USAGE
fi

if [ ! -d "${arch_dir}" ]; then
    echo "ERROR: '${arch_dir}' is not a directory"
    exit 65			# EX_DATAERR
fi

if [ -z ${elf_constants_file} ]; then
    elf_constants_file="${default_elfconstants_file}"
fi

if [ ! -f ${elf_constants_file} ]; then
    echo "ERROR: No such file '${elf_constants_file}'."
    exit 65			# EX_DATAERR
fi

if [ -z ${os_flavor} ]; then
    os_flavor=${default_os_flavor}
fi

case ${os_flavor} in
    NetBSD | FreeBSD )
	;;
    * )
	echo Unsupported OS: ${os_flavor}
	exit 65			# EX_DATAERR
	;;
esac

if [ -z ${symbol_type} ]; then
    symbol_type=${default_symbol_type}
fi

case ${symbol_type} in
    R)				# Relocations.
	;;
    *)
	echo Unimplemented symbol type ${symbol_type}.
	exit 69			# EX_UNAVAILABLE
esac

working_directory=$(mktemp -d -t ces.XXXXXXX)
trap "rm -rf ${working_directory}" EXIT HUP INT QUIT TERM

# Extract symbols of the desired type from the OS source tree and from
# Elftoolchain code.
arch_name=$(get_arch_name ${arch_dir})

elf_constants_symbols=${working_directory}/elf-constants-symbols
os_symbols=${working_directory}/os-symbols

case ${symbol_type} in
    R)
	relocation_prefix=$(get_relocation_prefix ${arch_name})

	(cd ${arch_dir} && \
	     get_os_symbols ${relocation_prefix}) > ${os_symbols}

	get_elf_constants ${relocation_prefix} > ${elf_constants_symbols}
	;;

    *)
	echo "ERROR: Unexpected symbol type '${symbol_type}'."
	exit 70			# EX_SOFTWARE
esac

# Compare symbol sets.
diff -wu ${os_symbols} ${elf_constants_symbols}
