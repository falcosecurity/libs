#
# Rules to build LateX documentation.
#
# $Id: elftoolchain.tex.mk 3907 2020-11-28 14:01:21Z jkoshy $
#

.include "${TOP}/mk/elftoolchain.os.mk"

.if defined(MKTEX) && ${MKTEX} == "yes" && exists(${MPOST}) && exists(${PDFLATEX})

TEXINPUTS=	`kpsepath tex`:${.CURDIR}
_TEX=		TEXINPUTS=${TEXINPUTS} ${PDFLATEX} -file-line-error \
			-halt-on-error

DOCSUBDIR=	elftoolchain	# Destination directory.
COVER_PAGE?=	1		# Cover page number in the document.
COVER_DPI?=	300		# Image resolution for cover page images.

.MAIN:	all

all:	${DOC}.pdf .PHONY

# Build an index.
#
# First, we need to remove the existing ".ind" file and run `latex` once
# to generate it afresh.  This generates the appropriate ".idx" files used
# by `makeindex`.
# Next, `makeindex` is used to create the ".ind" file.
# Then another set of `latex` runs serves to typeset the index.
index:	.PHONY
	rm -f ${DOC}.ind
	${_TEX} ${DOC}.tex
	${MAKEINDEX} ${DOC}.idx
	${_TEX} ${DOC}.tex
	@if grep 'Rerun to get' ${DOC}.log > /dev/null; then \
		${_TEX} ${DOC}.tex; \
	fi

# Cover page generation.
#
# Use the dedicated cover page if present.
.if exists(${DOC}.cover.tex)
${DOC}.cover.pdf: ${DOC}.cover.tex ${COVER_SRCS}
	${_TEX} ${.CURDIR}/${DOC}.cover.tex > /dev/null || \
		(cat ${DOC}.cover.log; rm -f ${.TARGET}; exit 1)
.else
# Otherwise, extract the cover page from the main document.
#
# This uses 'pdfjam' from the Tex Live package.
${DOC}.cover.pdf:	${DOC}.pdf ${GENERATED_VERSION_TEX} .PHONY
	${PDFJAM} -q -o ${DOC}.cover.pdf ${DOC}.pdf ${COVER_PAGE}
.endif

CLEANFILES+=	${DOC}.cover.pdf

# Converts the cover page to JPEG format, using US-Letter
# (8.5" x 11.0") dimensions.
#
# This step uses 'pdftoppm' from the Poppler package.
${DOC}.cover.usletter.jpeg:	${DOC}.cover.pdf .PHONY
	_W=$$(echo 8.5 '*' ${COVER_DPI} | bc | sed -e 's/\.[0-9]*$$//'); \
	_H=$$(echo 11.0 '*' ${COVER_DPI} | bc | sed -e 's/\.[0-9]*$$//'); \
	pdftoppm -r ${COVER_DPI} -jpeg -scale-to-x $${_W} -scale-to-y $${_H} \
		-aa yes -freetype yes ${DOC}.cover.pdf > ${.TARGET}

CLEANFILES+=	${DOC}.cover.usletter.jpeg

# Recognize additional suffixes.
.SUFFIXES:	.mp .eps .tex .pdf

# Rules to build MetaPost figures.
.mp.eps:
	@if [ "${.OBJDIR}" != "${.CURDIR}" ]; then cp ${.CURDIR}/${.IMPSRC:T} ${.OBJDIR}/; fi
	TEX=${MPOSTTEX} ${MPOST} -halt-on-error ${.IMPSRC:T} || (rm ${.IMPSRC:T:R}.1; false)
	mv ${.IMPSRC:T:R}.1 ${.TARGET}
.eps.pdf:
	${EPSTOPDF} ${.IMPSRC} > ${.TARGET} || (rm ${.TARGET}; false)

.for f in ${IMAGES_MP}
${f:R}.eps: ${.CURDIR}/${f}
CLEANFILES+=	${f:R}.eps ${f:R}.log ${f:R}.pdf ${f:R}.mpx
.endfor

CLEANFILES+=	mpxerr.tex mpxerr.log makempx.log missfont.log

${DOC}.pdf:	${SRCS} ${IMAGES_MP:S/.mp$/.pdf/g} ${GENERATED_VERSION_TEX}
	${_TEX} ${.CURDIR}/${DOC}.tex > /dev/null || \
		(cat ${DOC}.log; rm -f ${.TARGET}; exit 1)
	@if grep 'undefined references' ${DOC}.log > /dev/null; then \
		${_TEX} ${.CURDIR}/${DOC}.tex > /dev/null; \
	fi
	@if grep 'Rerun to get' ${DOC}.log > /dev/null; then \
		${_TEX} ${.CURDIR}/${DOC}.tex > /dev/null; \
	fi

.if defined(GENERATED_VERSION_TEX)
CLEANFILES+=	${GENERATED_VERSION_TEX}

${GENERATED_VERSION_TEX}:	.PHONY
	${.CURDIR}/${TOP}/libelftc/make-toolchain-version -t ${TOP} \
		-o ${.TARGET} -h '' -p
.endif

CLEANFILES+=	${DOC}.pdf

# Remove temporary files.
.for file in ${DOC} ${DOC}.cover ${COVER_SRCS:M*.tex:C/.tex$//1g}
.for ext in aux log out toc ind idx ilg
CLEANFILES+=	${file}.${ext}
.endfor
.endfor

# Do something sensible for the `depend` and `cleandepend` targets.
depend:		.depend
	@true
.depend:
	@echo ${DOC}.pdf: ${SRCS} ${IMAGES_MP:S/.mp$/.pdf/g} > ${.TARGET}
cleandepend:	.PHONY
	rm -f .depend

clean clobber:		.PHONY
	rm -f ${CLEANFILES}

install:	all
	@mkdir -p ${DESTDIR}/${DOCDIR}/${DOCSUBDIR}
	${INSTALL} -g ${DOCGRP} -o ${DOCOWN} ${DOC}.pdf \
		${DESTDIR}/${DOCDIR}/${DOCSUBDIR}

# Include rules for `make obj`
.include <bsd.obj.mk>

.else

all clean cleandepend clobber depend install obj: .PHONY .SILENT
	echo -n WARNING: make \"${.TARGET}\" in \"${.CURDIR:T}\" skipped:
.if	defined(MKTEX) && ${MKTEX} == "yes"
	echo " missing tools."
.else
	echo " builds of TeX documentation are disabled."
.endif
	true
.endif
