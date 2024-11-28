# $Id$
inittest elfcopy-keep-global-symbols tc/elfcopy-keep-global-symbols
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "${ELFCOPY} --keep-global-symbols=syms a.o b.o" work true
rundiff true
