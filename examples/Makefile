# Makefile.in generated by automake 1.13.4 from Makefile.am.
# examples/Makefile.  Generated from Makefile.in by configure.

# Copyright (C) 1994-2013 Free Software Foundation, Inc.

# This Makefile.in is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.



################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the ROHC example programs
################################################################################



am__is_gnu_make = test -n '$(MAKEFILE_LIST)' && test -n '$(MAKELEVEL)'
am__make_running_with_option = \
  case $${target_option-} in \
      ?) ;; \
      *) echo "am__make_running_with_option: internal error: invalid" \
              "target option '$${target_option-}' specified" >&2; \
         exit 1;; \
  esac; \
  has_opt=no; \
  sane_makeflags=$$MAKEFLAGS; \
  if $(am__is_gnu_make); then \
    sane_makeflags=$$MFLAGS; \
  else \
    case $$MAKEFLAGS in \
      *\\[\ \	]*) \
        bs=\\; \
        sane_makeflags=`printf '%s\n' "$$MAKEFLAGS" \
          | sed "s/$$bs$$bs[$$bs $$bs	]*//g"`;; \
    esac; \
  fi; \
  skip_next=no; \
  strip_trailopt () \
  { \
    flg=`printf '%s\n' "$$flg" | sed "s/$$1.*$$//"`; \
  }; \
  for flg in $$sane_makeflags; do \
    test $$skip_next = yes && { skip_next=no; continue; }; \
    case $$flg in \
      *=*|--*) continue;; \
        -*I) strip_trailopt 'I'; skip_next=yes;; \
      -*I?*) strip_trailopt 'I';; \
        -*O) strip_trailopt 'O'; skip_next=yes;; \
      -*O?*) strip_trailopt 'O';; \
        -*l) strip_trailopt 'l'; skip_next=yes;; \
      -*l?*) strip_trailopt 'l';; \
      -[dEDm]) skip_next=yes;; \
      -[JT]) skip_next=yes;; \
    esac; \
    case $$flg in \
      *$$target_option*) has_opt=yes; break;; \
    esac; \
  done; \
  test $$has_opt = yes
am__make_dryrun = (target_option=n; $(am__make_running_with_option))
am__make_keepgoing = (target_option=k; $(am__make_running_with_option))
pkgdatadir = $(datadir)/rohc
pkgincludedir = $(includedir)/rohc
pkglibdir = $(libdir)/rohc
pkglibexecdir = $(libexecdir)/rohc
am__cd = CDPATH="$${ZSH_VERSION+.}$(PATH_SEPARATOR)" && cd
install_sh_DATA = $(install_sh) -c -m 644
install_sh_PROGRAM = $(install_sh) -c
install_sh_SCRIPT = $(install_sh) -c
INSTALL_HEADER = $(INSTALL_DATA)
transform = $(program_transform_name)
NORMAL_INSTALL = :
PRE_INSTALL = :
POST_INSTALL = :
NORMAL_UNINSTALL = :
PRE_UNINSTALL = :
POST_UNINSTALL = :
build_triplet = x86_64-unknown-linux-gnu
host_triplet = x86_64-unknown-linux-gnu
noinst_PROGRAMS = simple_rohc_program$(EXEEXT) \
	print_rohc_version$(EXEEXT) example_rohc_decomp$(EXEEXT) \
	rtp_detection$(EXEEXT)
subdir = examples
DIST_COMMON = $(srcdir)/Makefile.in $(srcdir)/Makefile.am \
	$(top_srcdir)/depcomp
ACLOCAL_M4 = $(top_srcdir)/aclocal.m4
am__aclocal_m4_deps = $(top_srcdir)/configure.ac
am__configure_deps = $(am__aclocal_m4_deps) $(CONFIGURE_DEPENDENCIES) \
	$(ACLOCAL_M4)
mkinstalldirs = $(install_sh) -d
CONFIG_HEADER = $(top_builddir)/config.h
CONFIG_CLEAN_FILES =
CONFIG_CLEAN_VPATH_FILES =
PROGRAMS = $(noinst_PROGRAMS)
am_example_rohc_decomp_OBJECTS =  \
	example_rohc_decomp-example_rohc_decomp.$(OBJEXT)
example_rohc_decomp_OBJECTS = $(am_example_rohc_decomp_OBJECTS)
am__DEPENDENCIES_1 =
example_rohc_decomp_DEPENDENCIES = $(am__DEPENDENCIES_1)
AM_V_lt = $(am__v_lt_$(V))
am__v_lt_ = $(am__v_lt_$(AM_DEFAULT_VERBOSITY))
am__v_lt_0 = --silent
am__v_lt_1 = 
example_rohc_decomp_LINK = $(LIBTOOL) $(AM_V_lt) --tag=CC \
	$(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=link $(CCLD) \
	$(example_rohc_decomp_CFLAGS) $(CFLAGS) \
	$(example_rohc_decomp_LDFLAGS) $(LDFLAGS) -o $@
am_print_rohc_version_OBJECTS =  \
	print_rohc_version-print_rohc_version.$(OBJEXT)
print_rohc_version_OBJECTS = $(am_print_rohc_version_OBJECTS)
print_rohc_version_DEPENDENCIES = $(am__DEPENDENCIES_1)
print_rohc_version_LINK = $(LIBTOOL) $(AM_V_lt) --tag=CC \
	$(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=link $(CCLD) \
	$(print_rohc_version_CFLAGS) $(CFLAGS) \
	$(print_rohc_version_LDFLAGS) $(LDFLAGS) -o $@
am_rtp_detection_OBJECTS = rtp_detection-rtp_detection.$(OBJEXT)
rtp_detection_OBJECTS = $(am_rtp_detection_OBJECTS)
rtp_detection_DEPENDENCIES = $(am__DEPENDENCIES_1)
rtp_detection_LINK = $(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=link $(CCLD) $(rtp_detection_CFLAGS) \
	$(CFLAGS) $(rtp_detection_LDFLAGS) $(LDFLAGS) -o $@
am_simple_rohc_program_OBJECTS =  \
	simple_rohc_program-simple_rohc_program.$(OBJEXT)
simple_rohc_program_OBJECTS = $(am_simple_rohc_program_OBJECTS)
simple_rohc_program_DEPENDENCIES = $(am__DEPENDENCIES_1)
simple_rohc_program_LINK = $(LIBTOOL) $(AM_V_lt) --tag=CC \
	$(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=link $(CCLD) \
	$(simple_rohc_program_CFLAGS) $(CFLAGS) \
	$(simple_rohc_program_LDFLAGS) $(LDFLAGS) -o $@
AM_V_P = $(am__v_P_$(V))
am__v_P_ = $(am__v_P_$(AM_DEFAULT_VERBOSITY))
am__v_P_0 = false
am__v_P_1 = :
AM_V_GEN = $(am__v_GEN_$(V))
am__v_GEN_ = $(am__v_GEN_$(AM_DEFAULT_VERBOSITY))
am__v_GEN_0 = @echo "  GEN     " $@;
am__v_GEN_1 = 
AM_V_at = $(am__v_at_$(V))
am__v_at_ = $(am__v_at_$(AM_DEFAULT_VERBOSITY))
am__v_at_0 = @
am__v_at_1 = 
DEFAULT_INCLUDES = -I. -I$(top_builddir)
depcomp = $(SHELL) $(top_srcdir)/depcomp
am__depfiles_maybe = depfiles
am__mv = mv -f
COMPILE = $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	$(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
LTCOMPILE = $(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) \
	$(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) \
	$(AM_CFLAGS) $(CFLAGS)
AM_V_CC = $(am__v_CC_$(V))
am__v_CC_ = $(am__v_CC_$(AM_DEFAULT_VERBOSITY))
am__v_CC_0 = @echo "  CC      " $@;
am__v_CC_1 = 
CCLD = $(CC)
LINK = $(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=link $(CCLD) $(AM_CFLAGS) $(CFLAGS) \
	$(AM_LDFLAGS) $(LDFLAGS) -o $@
AM_V_CCLD = $(am__v_CCLD_$(V))
am__v_CCLD_ = $(am__v_CCLD_$(AM_DEFAULT_VERBOSITY))
am__v_CCLD_0 = @echo "  CCLD    " $@;
am__v_CCLD_1 = 
SOURCES = $(example_rohc_decomp_SOURCES) $(print_rohc_version_SOURCES) \
	$(rtp_detection_SOURCES) $(simple_rohc_program_SOURCES)
DIST_SOURCES = $(example_rohc_decomp_SOURCES) \
	$(print_rohc_version_SOURCES) $(rtp_detection_SOURCES) \
	$(simple_rohc_program_SOURCES)
am__can_run_installinfo = \
  case $$AM_UPDATE_INFO_DIR in \
    n|no|NO) false;; \
    *) (install-info --version) >/dev/null 2>&1;; \
  esac
am__vpath_adj_setup = srcdirstrip=`echo "$(srcdir)" | sed 's|.|.|g'`;
am__vpath_adj = case $$p in \
    $(srcdir)/*) f=`echo "$$p" | sed "s|^$$srcdirstrip/||"`;; \
    *) f=$$p;; \
  esac;
am__strip_dir = f=`echo $$p | sed -e 's|^.*/||'`;
am__install_max = 40
am__nobase_strip_setup = \
  srcdirstrip=`echo "$(srcdir)" | sed 's/[].[^$$\\*|]/\\\\&/g'`
am__nobase_strip = \
  for p in $$list; do echo "$$p"; done | sed -e "s|$$srcdirstrip/||"
am__nobase_list = $(am__nobase_strip_setup); \
  for p in $$list; do echo "$$p $$p"; done | \
  sed "s| $$srcdirstrip/| |;"' / .*\//!s/ .*/ ./; s,\( .*\)/[^/]*$$,\1,' | \
  $(AWK) 'BEGIN { files["."] = "" } { files[$$2] = files[$$2] " " $$1; \
    if (++n[$$2] == $(am__install_max)) \
      { print $$2, files[$$2]; n[$$2] = 0; files[$$2] = "" } } \
    END { for (dir in files) print dir, files[dir] }'
am__base_list = \
  sed '$$!N;$$!N;$$!N;$$!N;$$!N;$$!N;$$!N;s/\n/ /g' | \
  sed '$$!N;$$!N;$$!N;$$!N;s/\n/ /g'
am__uninstall_files_from_dir = { \
  test -z "$$files" \
    || { test ! -d "$$dir" && test ! -f "$$dir" && test ! -r "$$dir"; } \
    || { echo " ( cd '$$dir' && rm -f" $$files ")"; \
         $(am__cd) "$$dir" && rm -f $$files; }; \
  }
am__installdirs = "$(DESTDIR)$(examplesdir)"
DATA = $(examples_DATA)
am__tagged_files = $(HEADERS) $(SOURCES) $(TAGS_FILES) $(LISP)
# Read a list of newline-separated strings from the standard input,
# and print each of them once, without duplicates.  Input order is
# *not* preserved.
am__uniquify_input = $(AWK) '\
  BEGIN { nonempty = 0; } \
  { items[$$0] = 1; nonempty = 1; } \
  END { if (nonempty) { for (i in items) print i; }; } \
'
# Make sure the list of sources is unique.  This is necessary because,
# e.g., the same source file might be shared among _SOURCES variables
# for different programs/libraries.
am__define_uniq_tagged_files = \
  list='$(am__tagged_files)'; \
  unique=`for i in $$list; do \
    if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
  done | $(am__uniquify_input)`
ETAGS = etags
CTAGS = ctags
DISTFILES = $(DIST_COMMON) $(DIST_SOURCES) $(TEXINFOS) $(EXTRA_DIST)
ACLOCAL = ${SHELL} /home/sourav/Personal/Research/FinalSem/rohc-1.7.0/missing aclocal-1.13
AMTAR = $${TAR-tar}
AM_DEFAULT_VERBOSITY = 0
AR = ar
AS = as
AUTOCONF = ${SHELL} /home/sourav/Personal/Research/FinalSem/rohc-1.7.0/missing autoconf
AUTOHEADER = ${SHELL} /home/sourav/Personal/Research/FinalSem/rohc-1.7.0/missing autoheader
AUTOMAKE = ${SHELL} /home/sourav/Personal/Research/FinalSem/rohc-1.7.0/missing automake-1.13
AWK = gawk
CC = gcc -std=gnu99
CCDEPMODE = depmode=gcc3
CFLAGS = -g -O2
CMOCKA_CFLAGS = 
CMOCKA_LIBS = 
CPP = gcc -E
CPPFLAGS = 
CYGPATH_W = echo
DEFS = -DHAVE_CONFIG_H
DEPDIR = .deps
DLLTOOL = false
DSYMUTIL = 
DUMPBIN = 
ECHO_C = 
ECHO_N = -n
ECHO_T = 
EGREP = /usr/bin/grep -E
EXEEXT = 
FGREP = /usr/bin/grep -F
GREP = /usr/bin/grep
INSTALL = /usr/bin/install -c
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_PROGRAM = ${INSTALL}
INSTALL_SCRIPT = ${INSTALL}
INSTALL_STRIP_PROGRAM = $(install_sh) -c -s
LD = /usr/bin/ld -m elf_x86_64
LDFLAGS = 
LIBOBJS = 
LIBS = 
LIBTOOL = $(SHELL) $(top_builddir)/libtool
LIPO = 
LN_S = ln -s
LTLIBOBJS = 
MAKEINFO = ${SHELL} /home/sourav/Personal/Research/FinalSem/rohc-1.7.0/missing makeinfo
MANIFEST_TOOL = :
MKDIR_P = /usr/bin/mkdir -p
NM = /usr/bin/nm -B
NMEDIT = 
OBJDUMP = objdump
OBJEXT = o
OTOOL = 
OTOOL64 = 
PACKAGE = rohc
PACKAGE_BUGREPORT = http://rohc-lib.org/
PACKAGE_NAME = ROHC library
PACKAGE_REVNO = 
PACKAGE_STRING = ROHC library 1.7.0
PACKAGE_TARNAME = rohc
PACKAGE_URL = http://rohc-lib.org/
PACKAGE_VERSION = 1.7.0
PATH_SEPARATOR = :
PKG_CONFIG = 
PKG_CONFIG_LIBDIR = 
PKG_CONFIG_PATH = 
RANLIB = ranlib
ROHC_API_AGE = 2
ROHC_API_CURRENT = 2
ROHC_API_REVISION = 0
SED = /usr/bin/sed
SET_MAKE = 
SHELL = /bin/sh
STRIP = strip
TESTS_ENVIRONMENT =  GREP=/usr/bin/grep
VERSION = 1.7.0
abs_builddir = /home/sourav/Personal/Research/FinalSem/rohc-1.7.0/examples
abs_srcdir = /home/sourav/Personal/Research/FinalSem/rohc-1.7.0/examples
abs_top_builddir = /home/sourav/Personal/Research/FinalSem/rohc-1.7.0
abs_top_srcdir = /home/sourav/Personal/Research/FinalSem/rohc-1.7.0
ac_ct_AR = ar
ac_ct_CC = gcc
ac_ct_DUMPBIN = 
additional_platform_libs = 
am__include = include
am__leading_dot = .
am__quote = 
am__tar = tar --format=posix -chf - "$$tardir"
am__untar = tar -xf -
bindir = ${exec_prefix}/bin
build = x86_64-unknown-linux-gnu
build_alias = 
build_cpu = x86_64
build_os = linux-gnu
build_vendor = unknown
builddir = .
configure_cflags = -g -Wall -Wstrict-prototypes -Wextra -Wunreachable-code -Wunused-function -Wunused-variable -Wshadow -DROHC_ENABLE_DEPRECATED_API=1
configure_ldflags = 
datadir = ${datarootdir}
datarootdir = ${prefix}/share
docdir = ${datarootdir}/doc/${PACKAGE_TARNAME}
dvidir = ${docdir}
exec_prefix = ${prefix}
host = x86_64-unknown-linux-gnu
host_alias = 
host_cpu = x86_64
host_os = linux-gnu
host_vendor = unknown
htmldir = ${docdir}
includedir = ${prefix}/include
infodir = ${datarootdir}/info
install_sh = ${SHELL} /home/sourav/Personal/Research/FinalSem/rohc-1.7.0/install-sh
is_dot_found = 
is_doxy2man_found = 
is_doxygen_found = 
is_gnuplot_found = yes
is_help2man_found = 
is_latex_found = 
is_qemu_found = 
is_sort_found = yes
is_tr_found = yes
is_valgrind_found = 
is_wine_found = 
is_xsltproc_found = 
is_zcov_genhtml_found = 
is_zcov_scan_found = 
libdir = ${exec_prefix}/lib
libexecdir = ${exec_prefix}/libexec
libpcap_includes = 
linux_kernel_src = no
localedir = ${datarootdir}/locale
localstatedir = ${prefix}/var
mandir = ${datarootdir}/man
mkdir_p = $(MKDIR_P)
oldincludedir = /usr/include
pcap_lib_name = pcap
pdfdir = ${docdir}
prefix = /usr/local
program_transform_name = s,x,x,
psdir = ${docdir}
sbindir = ${exec_prefix}/sbin
sharedstatedir = ${prefix}/com
srcdir = .
sysconfdir = ${prefix}/etc
target_alias = 
top_build_prefix = ../
top_builddir = ..
top_srcdir = ..
examplesdir = $(docdir)/examples
examples_DATA = \
	simple_rohc_program.c \
	print_rohc_version.c \
	example_rohc_decomp.c \
	rtp_detection.c

simple_rohc_program_CFLAGS = \
	$(configure_cflags) \
	-Wno-unused-parameter

simple_rohc_program_CPPFLAGS = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp

simple_rohc_program_LDFLAGS = \
	$(configure_ldflags) \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs

simple_rohc_program_SOURCES = \
	simple_rohc_program.c

simple_rohc_program_LDADD = \
	-lrohc_comp \
	-lrohc_common \
	$(additional_platform_libs)

print_rohc_version_CFLAGS = \
	$(configure_cflags) \
	-Wno-unused-parameter

print_rohc_version_CPPFLAGS = \
	-I$(top_srcdir)/src/common

print_rohc_version_LDFLAGS = \
	$(configure_ldflags) \
	-L$(top_builddir)/src/common/.libs

print_rohc_version_SOURCES = \
	print_rohc_version.c

print_rohc_version_LDADD = \
	-lrohc_common \
	$(additional_platform_libs)

example_rohc_decomp_CFLAGS = \
	$(configure_cflags) \
	-Wno-unused-parameter

example_rohc_decomp_CPPFLAGS = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp

example_rohc_decomp_LDFLAGS = \
	$(configure_ldflags) \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs \
	-L$(top_builddir)/src/decomp/.libs

example_rohc_decomp_SOURCES = \
	example_rohc_decomp.c

example_rohc_decomp_LDADD = \
	-lrohc_decomp \
	-lrohc_comp \
	-lrohc_common \
	$(additional_platform_libs)

rtp_detection_CFLAGS = \
	$(configure_cflags) \
	-Wno-unused-parameter

rtp_detection_CPPFLAGS = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp

rtp_detection_LDFLAGS = \
	$(configure_ldflags) \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs

rtp_detection_SOURCES = \
	rtp_detection.c

rtp_detection_LDADD = \
	-lrohc_comp \
	-lrohc_common \
	$(additional_platform_libs)

all: all-am

.SUFFIXES:
.SUFFIXES: .c .lo .o .obj
$(srcdir)/Makefile.in:  $(srcdir)/Makefile.am  $(am__configure_deps)
	@for dep in $?; do \
	  case '$(am__configure_deps)' in \
	    *$$dep*) \
	      ( cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh ) \
	        && { if test -f $@; then exit 0; else break; fi; }; \
	      exit 1;; \
	  esac; \
	done; \
	echo ' cd $(top_srcdir) && $(AUTOMAKE) --foreign examples/Makefile'; \
	$(am__cd) $(top_srcdir) && \
	  $(AUTOMAKE) --foreign examples/Makefile
.PRECIOUS: Makefile
Makefile: $(srcdir)/Makefile.in $(top_builddir)/config.status
	@case '$?' in \
	  *config.status*) \
	    cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh;; \
	  *) \
	    echo ' cd $(top_builddir) && $(SHELL) ./config.status $(subdir)/$@ $(am__depfiles_maybe)'; \
	    cd $(top_builddir) && $(SHELL) ./config.status $(subdir)/$@ $(am__depfiles_maybe);; \
	esac;

$(top_builddir)/config.status: $(top_srcdir)/configure $(CONFIG_STATUS_DEPENDENCIES)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh

$(top_srcdir)/configure:  $(am__configure_deps)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh
$(ACLOCAL_M4):  $(am__aclocal_m4_deps)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh
$(am__aclocal_m4_deps):

clean-noinstPROGRAMS:
	@list='$(noinst_PROGRAMS)'; test -n "$$list" || exit 0; \
	echo " rm -f" $$list; \
	rm -f $$list || exit $$?; \
	test -n "$(EXEEXT)" || exit 0; \
	list=`for p in $$list; do echo "$$p"; done | sed 's/$(EXEEXT)$$//'`; \
	echo " rm -f" $$list; \
	rm -f $$list

example_rohc_decomp$(EXEEXT): $(example_rohc_decomp_OBJECTS) $(example_rohc_decomp_DEPENDENCIES) $(EXTRA_example_rohc_decomp_DEPENDENCIES) 
	@rm -f example_rohc_decomp$(EXEEXT)
	$(AM_V_CCLD)$(example_rohc_decomp_LINK) $(example_rohc_decomp_OBJECTS) $(example_rohc_decomp_LDADD) $(LIBS)

print_rohc_version$(EXEEXT): $(print_rohc_version_OBJECTS) $(print_rohc_version_DEPENDENCIES) $(EXTRA_print_rohc_version_DEPENDENCIES) 
	@rm -f print_rohc_version$(EXEEXT)
	$(AM_V_CCLD)$(print_rohc_version_LINK) $(print_rohc_version_OBJECTS) $(print_rohc_version_LDADD) $(LIBS)

rtp_detection$(EXEEXT): $(rtp_detection_OBJECTS) $(rtp_detection_DEPENDENCIES) $(EXTRA_rtp_detection_DEPENDENCIES) 
	@rm -f rtp_detection$(EXEEXT)
	$(AM_V_CCLD)$(rtp_detection_LINK) $(rtp_detection_OBJECTS) $(rtp_detection_LDADD) $(LIBS)

simple_rohc_program$(EXEEXT): $(simple_rohc_program_OBJECTS) $(simple_rohc_program_DEPENDENCIES) $(EXTRA_simple_rohc_program_DEPENDENCIES) 
	@rm -f simple_rohc_program$(EXEEXT)
	$(AM_V_CCLD)$(simple_rohc_program_LINK) $(simple_rohc_program_OBJECTS) $(simple_rohc_program_LDADD) $(LIBS)

mostlyclean-compile:
	-rm -f *.$(OBJEXT)

distclean-compile:
	-rm -f *.tab.c

include ./$(DEPDIR)/example_rohc_decomp-example_rohc_decomp.Po
include ./$(DEPDIR)/print_rohc_version-print_rohc_version.Po
include ./$(DEPDIR)/rtp_detection-rtp_detection.Po
include ./$(DEPDIR)/simple_rohc_program-simple_rohc_program.Po

.c.o:
	$(AM_V_CC)$(COMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ $<
	$(AM_V_at)$(am__mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Po
#	$(AM_V_CC)source='$<' object='$@' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(COMPILE) -c $<

.c.obj:
	$(AM_V_CC)$(COMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ `$(CYGPATH_W) '$<'`
	$(AM_V_at)$(am__mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Po
#	$(AM_V_CC)source='$<' object='$@' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(COMPILE) -c `$(CYGPATH_W) '$<'`

.c.lo:
	$(AM_V_CC)$(LTCOMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ $<
	$(AM_V_at)$(am__mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Plo
#	$(AM_V_CC)source='$<' object='$@' libtool=yes \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(LTCOMPILE) -c -o $@ $<

example_rohc_decomp-example_rohc_decomp.o: example_rohc_decomp.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(example_rohc_decomp_CPPFLAGS) $(CPPFLAGS) $(example_rohc_decomp_CFLAGS) $(CFLAGS) -MT example_rohc_decomp-example_rohc_decomp.o -MD -MP -MF $(DEPDIR)/example_rohc_decomp-example_rohc_decomp.Tpo -c -o example_rohc_decomp-example_rohc_decomp.o `test -f 'example_rohc_decomp.c' || echo '$(srcdir)/'`example_rohc_decomp.c
	$(AM_V_at)$(am__mv) $(DEPDIR)/example_rohc_decomp-example_rohc_decomp.Tpo $(DEPDIR)/example_rohc_decomp-example_rohc_decomp.Po
#	$(AM_V_CC)source='example_rohc_decomp.c' object='example_rohc_decomp-example_rohc_decomp.o' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(example_rohc_decomp_CPPFLAGS) $(CPPFLAGS) $(example_rohc_decomp_CFLAGS) $(CFLAGS) -c -o example_rohc_decomp-example_rohc_decomp.o `test -f 'example_rohc_decomp.c' || echo '$(srcdir)/'`example_rohc_decomp.c

example_rohc_decomp-example_rohc_decomp.obj: example_rohc_decomp.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(example_rohc_decomp_CPPFLAGS) $(CPPFLAGS) $(example_rohc_decomp_CFLAGS) $(CFLAGS) -MT example_rohc_decomp-example_rohc_decomp.obj -MD -MP -MF $(DEPDIR)/example_rohc_decomp-example_rohc_decomp.Tpo -c -o example_rohc_decomp-example_rohc_decomp.obj `if test -f 'example_rohc_decomp.c'; then $(CYGPATH_W) 'example_rohc_decomp.c'; else $(CYGPATH_W) '$(srcdir)/example_rohc_decomp.c'; fi`
	$(AM_V_at)$(am__mv) $(DEPDIR)/example_rohc_decomp-example_rohc_decomp.Tpo $(DEPDIR)/example_rohc_decomp-example_rohc_decomp.Po
#	$(AM_V_CC)source='example_rohc_decomp.c' object='example_rohc_decomp-example_rohc_decomp.obj' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(example_rohc_decomp_CPPFLAGS) $(CPPFLAGS) $(example_rohc_decomp_CFLAGS) $(CFLAGS) -c -o example_rohc_decomp-example_rohc_decomp.obj `if test -f 'example_rohc_decomp.c'; then $(CYGPATH_W) 'example_rohc_decomp.c'; else $(CYGPATH_W) '$(srcdir)/example_rohc_decomp.c'; fi`

print_rohc_version-print_rohc_version.o: print_rohc_version.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(print_rohc_version_CPPFLAGS) $(CPPFLAGS) $(print_rohc_version_CFLAGS) $(CFLAGS) -MT print_rohc_version-print_rohc_version.o -MD -MP -MF $(DEPDIR)/print_rohc_version-print_rohc_version.Tpo -c -o print_rohc_version-print_rohc_version.o `test -f 'print_rohc_version.c' || echo '$(srcdir)/'`print_rohc_version.c
	$(AM_V_at)$(am__mv) $(DEPDIR)/print_rohc_version-print_rohc_version.Tpo $(DEPDIR)/print_rohc_version-print_rohc_version.Po
#	$(AM_V_CC)source='print_rohc_version.c' object='print_rohc_version-print_rohc_version.o' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(print_rohc_version_CPPFLAGS) $(CPPFLAGS) $(print_rohc_version_CFLAGS) $(CFLAGS) -c -o print_rohc_version-print_rohc_version.o `test -f 'print_rohc_version.c' || echo '$(srcdir)/'`print_rohc_version.c

print_rohc_version-print_rohc_version.obj: print_rohc_version.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(print_rohc_version_CPPFLAGS) $(CPPFLAGS) $(print_rohc_version_CFLAGS) $(CFLAGS) -MT print_rohc_version-print_rohc_version.obj -MD -MP -MF $(DEPDIR)/print_rohc_version-print_rohc_version.Tpo -c -o print_rohc_version-print_rohc_version.obj `if test -f 'print_rohc_version.c'; then $(CYGPATH_W) 'print_rohc_version.c'; else $(CYGPATH_W) '$(srcdir)/print_rohc_version.c'; fi`
	$(AM_V_at)$(am__mv) $(DEPDIR)/print_rohc_version-print_rohc_version.Tpo $(DEPDIR)/print_rohc_version-print_rohc_version.Po
#	$(AM_V_CC)source='print_rohc_version.c' object='print_rohc_version-print_rohc_version.obj' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(print_rohc_version_CPPFLAGS) $(CPPFLAGS) $(print_rohc_version_CFLAGS) $(CFLAGS) -c -o print_rohc_version-print_rohc_version.obj `if test -f 'print_rohc_version.c'; then $(CYGPATH_W) 'print_rohc_version.c'; else $(CYGPATH_W) '$(srcdir)/print_rohc_version.c'; fi`

rtp_detection-rtp_detection.o: rtp_detection.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(rtp_detection_CPPFLAGS) $(CPPFLAGS) $(rtp_detection_CFLAGS) $(CFLAGS) -MT rtp_detection-rtp_detection.o -MD -MP -MF $(DEPDIR)/rtp_detection-rtp_detection.Tpo -c -o rtp_detection-rtp_detection.o `test -f 'rtp_detection.c' || echo '$(srcdir)/'`rtp_detection.c
	$(AM_V_at)$(am__mv) $(DEPDIR)/rtp_detection-rtp_detection.Tpo $(DEPDIR)/rtp_detection-rtp_detection.Po
#	$(AM_V_CC)source='rtp_detection.c' object='rtp_detection-rtp_detection.o' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(rtp_detection_CPPFLAGS) $(CPPFLAGS) $(rtp_detection_CFLAGS) $(CFLAGS) -c -o rtp_detection-rtp_detection.o `test -f 'rtp_detection.c' || echo '$(srcdir)/'`rtp_detection.c

rtp_detection-rtp_detection.obj: rtp_detection.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(rtp_detection_CPPFLAGS) $(CPPFLAGS) $(rtp_detection_CFLAGS) $(CFLAGS) -MT rtp_detection-rtp_detection.obj -MD -MP -MF $(DEPDIR)/rtp_detection-rtp_detection.Tpo -c -o rtp_detection-rtp_detection.obj `if test -f 'rtp_detection.c'; then $(CYGPATH_W) 'rtp_detection.c'; else $(CYGPATH_W) '$(srcdir)/rtp_detection.c'; fi`
	$(AM_V_at)$(am__mv) $(DEPDIR)/rtp_detection-rtp_detection.Tpo $(DEPDIR)/rtp_detection-rtp_detection.Po
#	$(AM_V_CC)source='rtp_detection.c' object='rtp_detection-rtp_detection.obj' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(rtp_detection_CPPFLAGS) $(CPPFLAGS) $(rtp_detection_CFLAGS) $(CFLAGS) -c -o rtp_detection-rtp_detection.obj `if test -f 'rtp_detection.c'; then $(CYGPATH_W) 'rtp_detection.c'; else $(CYGPATH_W) '$(srcdir)/rtp_detection.c'; fi`

simple_rohc_program-simple_rohc_program.o: simple_rohc_program.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(simple_rohc_program_CPPFLAGS) $(CPPFLAGS) $(simple_rohc_program_CFLAGS) $(CFLAGS) -MT simple_rohc_program-simple_rohc_program.o -MD -MP -MF $(DEPDIR)/simple_rohc_program-simple_rohc_program.Tpo -c -o simple_rohc_program-simple_rohc_program.o `test -f 'simple_rohc_program.c' || echo '$(srcdir)/'`simple_rohc_program.c
	$(AM_V_at)$(am__mv) $(DEPDIR)/simple_rohc_program-simple_rohc_program.Tpo $(DEPDIR)/simple_rohc_program-simple_rohc_program.Po
#	$(AM_V_CC)source='simple_rohc_program.c' object='simple_rohc_program-simple_rohc_program.o' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(simple_rohc_program_CPPFLAGS) $(CPPFLAGS) $(simple_rohc_program_CFLAGS) $(CFLAGS) -c -o simple_rohc_program-simple_rohc_program.o `test -f 'simple_rohc_program.c' || echo '$(srcdir)/'`simple_rohc_program.c

simple_rohc_program-simple_rohc_program.obj: simple_rohc_program.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(simple_rohc_program_CPPFLAGS) $(CPPFLAGS) $(simple_rohc_program_CFLAGS) $(CFLAGS) -MT simple_rohc_program-simple_rohc_program.obj -MD -MP -MF $(DEPDIR)/simple_rohc_program-simple_rohc_program.Tpo -c -o simple_rohc_program-simple_rohc_program.obj `if test -f 'simple_rohc_program.c'; then $(CYGPATH_W) 'simple_rohc_program.c'; else $(CYGPATH_W) '$(srcdir)/simple_rohc_program.c'; fi`
	$(AM_V_at)$(am__mv) $(DEPDIR)/simple_rohc_program-simple_rohc_program.Tpo $(DEPDIR)/simple_rohc_program-simple_rohc_program.Po
#	$(AM_V_CC)source='simple_rohc_program.c' object='simple_rohc_program-simple_rohc_program.obj' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(simple_rohc_program_CPPFLAGS) $(CPPFLAGS) $(simple_rohc_program_CFLAGS) $(CFLAGS) -c -o simple_rohc_program-simple_rohc_program.obj `if test -f 'simple_rohc_program.c'; then $(CYGPATH_W) 'simple_rohc_program.c'; else $(CYGPATH_W) '$(srcdir)/simple_rohc_program.c'; fi`

mostlyclean-libtool:
	-rm -f *.lo

clean-libtool:
	-rm -rf .libs _libs
install-examplesDATA: $(examples_DATA)
	@$(NORMAL_INSTALL)
	@list='$(examples_DATA)'; test -n "$(examplesdir)" || list=; \
	if test -n "$$list"; then \
	  echo " $(MKDIR_P) '$(DESTDIR)$(examplesdir)'"; \
	  $(MKDIR_P) "$(DESTDIR)$(examplesdir)" || exit 1; \
	fi; \
	for p in $$list; do \
	  if test -f "$$p"; then d=; else d="$(srcdir)/"; fi; \
	  echo "$$d$$p"; \
	done | $(am__base_list) | \
	while read files; do \
	  echo " $(INSTALL_DATA) $$files '$(DESTDIR)$(examplesdir)'"; \
	  $(INSTALL_DATA) $$files "$(DESTDIR)$(examplesdir)" || exit $$?; \
	done

uninstall-examplesDATA:
	@$(NORMAL_UNINSTALL)
	@list='$(examples_DATA)'; test -n "$(examplesdir)" || list=; \
	files=`for p in $$list; do echo $$p; done | sed -e 's|^.*/||'`; \
	dir='$(DESTDIR)$(examplesdir)'; $(am__uninstall_files_from_dir)

ID: $(am__tagged_files)
	$(am__define_uniq_tagged_files); mkid -fID $$unique
tags: tags-am
TAGS: tags

tags-am: $(TAGS_DEPENDENCIES) $(am__tagged_files)
	set x; \
	here=`pwd`; \
	$(am__define_uniq_tagged_files); \
	shift; \
	if test -z "$(ETAGS_ARGS)$$*$$unique"; then :; else \
	  test -n "$$unique" || unique=$$empty_fix; \
	  if test $$# -gt 0; then \
	    $(ETAGS) $(ETAGSFLAGS) $(AM_ETAGSFLAGS) $(ETAGS_ARGS) \
	      "$$@" $$unique; \
	  else \
	    $(ETAGS) $(ETAGSFLAGS) $(AM_ETAGSFLAGS) $(ETAGS_ARGS) \
	      $$unique; \
	  fi; \
	fi
ctags: ctags-am

CTAGS: ctags
ctags-am: $(TAGS_DEPENDENCIES) $(am__tagged_files)
	$(am__define_uniq_tagged_files); \
	test -z "$(CTAGS_ARGS)$$unique" \
	  || $(CTAGS) $(CTAGSFLAGS) $(AM_CTAGSFLAGS) $(CTAGS_ARGS) \
	     $$unique

GTAGS:
	here=`$(am__cd) $(top_builddir) && pwd` \
	  && $(am__cd) $(top_srcdir) \
	  && gtags -i $(GTAGS_ARGS) "$$here"
cscopelist: cscopelist-am

cscopelist-am: $(am__tagged_files)
	list='$(am__tagged_files)'; \
	case "$(srcdir)" in \
	  [\\/]* | ?:[\\/]*) sdir="$(srcdir)" ;; \
	  *) sdir=$(subdir)/$(srcdir) ;; \
	esac; \
	for i in $$list; do \
	  if test -f "$$i"; then \
	    echo "$(subdir)/$$i"; \
	  else \
	    echo "$$sdir/$$i"; \
	  fi; \
	done >> $(top_builddir)/cscope.files

distclean-tags:
	-rm -f TAGS ID GTAGS GRTAGS GSYMS GPATH tags

distdir: $(DISTFILES)
	@srcdirstrip=`echo "$(srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	topsrcdirstrip=`echo "$(top_srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	list='$(DISTFILES)'; \
	  dist_files=`for file in $$list; do echo $$file; done | \
	  sed -e "s|^$$srcdirstrip/||;t" \
	      -e "s|^$$topsrcdirstrip/|$(top_builddir)/|;t"`; \
	case $$dist_files in \
	  */*) $(MKDIR_P) `echo "$$dist_files" | \
			   sed '/\//!d;s|^|$(distdir)/|;s,/[^/]*$$,,' | \
			   sort -u` ;; \
	esac; \
	for file in $$dist_files; do \
	  if test -f $$file || test -d $$file; then d=.; else d=$(srcdir); fi; \
	  if test -d $$d/$$file; then \
	    dir=`echo "/$$file" | sed -e 's,/[^/]*$$,,'`; \
	    if test -d "$(distdir)/$$file"; then \
	      find "$(distdir)/$$file" -type d ! -perm -700 -exec chmod u+rwx {} \;; \
	    fi; \
	    if test -d $(srcdir)/$$file && test $$d != $(srcdir); then \
	      cp -fpR $(srcdir)/$$file "$(distdir)$$dir" || exit 1; \
	      find "$(distdir)/$$file" -type d ! -perm -700 -exec chmod u+rwx {} \;; \
	    fi; \
	    cp -fpR $$d/$$file "$(distdir)$$dir" || exit 1; \
	  else \
	    test -f "$(distdir)/$$file" \
	    || cp -p $$d/$$file "$(distdir)/$$file" \
	    || exit 1; \
	  fi; \
	done
check-am: all-am
check: check-am
all-am: Makefile $(PROGRAMS) $(DATA)
installdirs:
	for dir in "$(DESTDIR)$(examplesdir)"; do \
	  test -z "$$dir" || $(MKDIR_P) "$$dir"; \
	done
install: install-am
install-exec: install-exec-am
install-data: install-data-am
uninstall: uninstall-am

install-am: all-am
	@$(MAKE) $(AM_MAKEFLAGS) install-exec-am install-data-am

installcheck: installcheck-am
install-strip:
	if test -z '$(STRIP)'; then \
	  $(MAKE) $(AM_MAKEFLAGS) INSTALL_PROGRAM="$(INSTALL_STRIP_PROGRAM)" \
	    install_sh_PROGRAM="$(INSTALL_STRIP_PROGRAM)" INSTALL_STRIP_FLAG=-s \
	      install; \
	else \
	  $(MAKE) $(AM_MAKEFLAGS) INSTALL_PROGRAM="$(INSTALL_STRIP_PROGRAM)" \
	    install_sh_PROGRAM="$(INSTALL_STRIP_PROGRAM)" INSTALL_STRIP_FLAG=-s \
	    "INSTALL_PROGRAM_ENV=STRIPPROG='$(STRIP)'" install; \
	fi
mostlyclean-generic:

clean-generic:

distclean-generic:
	-test -z "$(CONFIG_CLEAN_FILES)" || rm -f $(CONFIG_CLEAN_FILES)
	-test . = "$(srcdir)" || test -z "$(CONFIG_CLEAN_VPATH_FILES)" || rm -f $(CONFIG_CLEAN_VPATH_FILES)

maintainer-clean-generic:
	@echo "This command is intended for maintainers to use"
	@echo "it deletes files that may require special tools to rebuild."
clean: clean-am

clean-am: clean-generic clean-libtool clean-noinstPROGRAMS \
	mostlyclean-am

distclean: distclean-am
	-rm -rf ./$(DEPDIR)
	-rm -f Makefile
distclean-am: clean-am distclean-compile distclean-generic \
	distclean-tags

dvi: dvi-am

dvi-am:

html: html-am

html-am:

info: info-am

info-am:

install-data-am: install-examplesDATA

install-dvi: install-dvi-am

install-dvi-am:

install-exec-am:

install-html: install-html-am

install-html-am:

install-info: install-info-am

install-info-am:

install-man:

install-pdf: install-pdf-am

install-pdf-am:

install-ps: install-ps-am

install-ps-am:

installcheck-am:

maintainer-clean: maintainer-clean-am
	-rm -rf ./$(DEPDIR)
	-rm -f Makefile
maintainer-clean-am: distclean-am maintainer-clean-generic

mostlyclean: mostlyclean-am

mostlyclean-am: mostlyclean-compile mostlyclean-generic \
	mostlyclean-libtool

pdf: pdf-am

pdf-am:

ps: ps-am

ps-am:

uninstall-am: uninstall-examplesDATA

.MAKE: install-am install-strip

.PHONY: CTAGS GTAGS TAGS all all-am check check-am clean clean-generic \
	clean-libtool clean-noinstPROGRAMS cscopelist-am ctags \
	ctags-am distclean distclean-compile distclean-generic \
	distclean-libtool distclean-tags distdir dvi dvi-am html \
	html-am info info-am install install-am install-data \
	install-data-am install-dvi install-dvi-am \
	install-examplesDATA install-exec install-exec-am install-html \
	install-html-am install-info install-info-am install-man \
	install-pdf install-pdf-am install-ps install-ps-am \
	install-strip installcheck installcheck-am installdirs \
	maintainer-clean maintainer-clean-generic mostlyclean \
	mostlyclean-compile mostlyclean-generic mostlyclean-libtool \
	pdf pdf-am ps ps-am tags tags-am uninstall uninstall-am \
	uninstall-examplesDATA


# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
