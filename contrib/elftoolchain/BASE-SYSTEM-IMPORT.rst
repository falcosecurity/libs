Importing Elftoolchain Code
===========================

Downstream operating system projects often import Elftoolchain code
into their 'base system' source tree.  Such imports often involve
project-specific modifications to Elftoolchain source code, e.g. the
addition of project-specific version control identifiers, the use of
project-specific headers, and so on.

This document describes the placeholders that are present in the
Elftoolchain project's source code that help automate source code imports.


List of placeholders
--------------------

@ELFTC-DECLARE-DOWNSTREAM-VCSID@

  A placeholder to be replaced with the definition of the downstream
  project's version control system ID.

  E.g. on NetBSD this placeholder could be replaced with::

     #if !defined(__RCSID)
     #define __RCSID(ID) /**/
     #endif

@ELFTC-DEFINE-ELFTC-VCSID@

  This placeholder is meant to be replaced by a project-specific
  definition of the ``ELFTC_VCSID()`` macro if the default definition
  needs to be overridden.

@ELFTC-USE-DOWNSTREAM-VCSID@

  A placeholder to be replaced by the use of the downstream project's
  version control ID.

  E.g. on NetBSD this placeholder could be replaced with::

    __RCSID("$NetBSD$");

@ELFTC-INCLUDE-SYS-CDEFS@

  Some projects define their copyright and revision control macros
  in ``<sys/cdefs.h>``, and mandate that these macros should appear
  immediately after any copyright text.  Such projects can replace this
  placeholder with the appropriate ``#include`` statement.

@LIBELF-DEFINE-HOST-BYTEORDER@

  A placeholder to be replaced by the downstream project's method to
  determine the runtime byte order to use (ELF2LSB or ELF2MSB).

  Projects using GCC or CLANG would not ordinarily need to use this
  placeholder.

.. $Id$

.. Local Variables:
.. mode: rst
.. End:
