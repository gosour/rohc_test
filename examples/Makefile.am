################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the ROHC example programs
################################################################################

examplesdir = $(docdir)/examples

examples_DATA = \
	simple_rohc_program.c \
	print_rohc_version.c \
	example_rohc_decomp.c \
	rtp_detection.c

noinst_PROGRAMS = \
	simple_rohc_program \
	print_rohc_version \
	example_rohc_decomp \
	rtp_detection


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

