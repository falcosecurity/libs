#!/bin/sh
#
# Turn Elftoolchain's manual pages into a collection of static HTML pages.

#
# Helper functions.
#
usage()
{
    exec >&2

    # Print the supplied message, if present.
    if [ -n "${@}" ]; then echo "## ${@}"; fi

    echo "Usage: ${progname} -t TOPDIR [options]"

    exit 1
}

log()
{
    if [ -z "${verbose}" ]; then return; fi
    echo $*
}

# Locate a BSD make.
bsdmakepath()
{
    case `uname -s` in
	FreeBSD|Minix|NetBSD|OpenBSD|DragonFly)
	    which make;;
	Linux ) which bmake;;
	* ) usage "ERROR: Unsupported operating system.";;
    esac
}

# Replace a header element with an SF logo invocation.
add_sf_link()
{
    sed -e 's,\(<td class="head-rtitle">\).*</td>,\1<img alt="SourceForge Logo" src="https://sourceforge.net/sflogo.php?type=13\&group_id=221879"></td>,'
}

#
# Defaults.
#
options='c:o:t:v'
css_file='mandoc.css'
output_dir=''
verbose=''
make=`bsdmakepath`

#
# Parse options.
#
while getopts ${options} option
do
    case ${option} in
	'c') css_file="${OPTARG}";;
	'm') make="${OPTARG}";;
	'o') output_dir="${OPTARG}";;
	't') top="${OPTARG}";;
	'v') verbose=TRUE;;
    esac
done

[ -n "${top}" ] || usage "The -t flag was not specified."

curdir=`pwd`
if [ -z "${output_dir}" ]; then output_dir="${curdir}/man"; fi

# Create the staging directory and copy the CSS specification into it.
mkdir -p ${output_dir} || \
    usage "ERROR: Cannot create output directory \"${output_dir}\"."
cp ${css_file} ${output_dir} || \
    usage "ERROR: Could not copy \"${css_file}\" to \"${output_dir}\"."

# List the manual pages to be converted to HTML.
#
# This stanza selects all file names ending in ".<digit>", which may be
# too permissive.
cd ${top} || usage "ERROR: Cannot change directory to \"${top}\"."
man_srcs=$(find . -name tet -prune -o -type f -name '*.[0-9]' -print)

# Translate manual pages to HTML.
for m in ${man_srcs}; do
    b=$(basename ${m})
    log Translating ${m}
    mandoc -Thtml -O style=${css_file##*/},man=%N.%S.html -mdoc \
	   -I os='The Elftoolchain Project' ${m} | \
	add_sf_link > ${output_dir}/${b}.html
done

# Add MLINKS.
#
# Create a list of directories containing the manual pages being
# translated.
man_dirs=$(echo "$man_srcs" | sed -e 's,/[^/]*$,,' | sort -u)

# The output from invoking 'make -V $MLINKS' is a sequence of
# (source, target) pairs of manual page names.
for d in ${man_dirs}; do
    log Adding MLINKS for ${d}
    mlinks=$(cd ${d} && ${make} -V '${MLINKS}') || \
	usage "ERROR: Failed to extract MLINKS for ${d}"
    set -- ${mlinks}
    while [ ${#} -gt 0 ]; do
        log Linking ${2} to ${1}
        (cd ${output_dir}; ln -fs ${1}.html ${2}.html);
        shift; shift;
    done
done

# Build an index.
log Building an index

cd ${output_dir} || \
    usage "ERROR: Could not change directory to \"${output_dir}\"."

# Write out the HTML prologue.
cat > index.html <<EOF
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8"/>
  <style>
    table.head, table.foot { width: 100%; }
    td.head-rtitle, td.foot-os { text-align: right; }
    td.head-vol { text-align: center; }
    div.Pp { margin: 1ex 0ex; }
  </style>
  <link rel="stylesheet" href="mandoc.css" type="text/css" media="all"/>
  <title>INDEX</title>
</head>
<body>
<table class="head">
  <tr>
    <td class="head-ltitle">Manual Page Index</td>
    <td class="head-rtitle"><img alt="SourceForge Logo"
        src="https://sourceforge.net/sflogo.php?type=13&group_id=221879">
    </td>
  </tr>
</table>
<div>
<dl class="Bl-tag">
EOF

# Build <dt> elements for each generated HTML file.
for h in $(ls *.[0-9].html); do
    hxextract -s "<dt><a href=\"$h\">${h%.html}</a></dt><dd>" \
	      -e "</dd>" span.Nd ${h}
    echo
done >> index.html

# Write out the epilogue.
cat >> index.html <<EOF
</dl>
</div>
</body>
</html>
EOF
