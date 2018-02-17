#.rst:
# FindHoel
# -----------
#
# Find Hoel
#
# Find Hoel headers and libraries.
#
# ::
#
#   HOEL_FOUND          - True if Hoel found.
#   HOEL_INCLUDE_DIRS   - Where to find hoel.h.
#   HOEL_LIBRARIES      - List of libraries when using Hoel.
#   HOEL_VERSION_STRING - The version of Hoel found.

#=============================================================================
# Copyright 2018 Nicolas Mora <mail@babelouest.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation;
# version 2.1 of the License.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
# GNU GENERAL PUBLIC LICENSE for more details.
#
# You should have received a copy of the GNU General Public
# License along with this library.	If not, see <http://www.gnu.org/licenses/>.
#=============================================================================

find_package(PkgConfig QUIET)
pkg_check_modules(PC_HOEL QUIET hoel)

find_path(HOEL_INCLUDE_DIR
        NAMES hoel.h
        HINTS ${PC_HOEL_INCLUDEDIR} ${PC_HOEL_INCLUDE_DIRS})

find_library(HOEL_LIBRARY
        NAMES hoel libhoel
        HINTS ${PC_HOEL_LIBDIR} ${PC_HOEL_LIBRARY_DIRS})

set(HOEL_VERSION_STRING 0.0.0)
if (PC_HOEL_VERSION)
    set(HOEL_VERSION_STRING ${PC_HOEL_VERSION})
elseif (HOEL_INCLUDE_DIR AND EXISTS "${HOEL_INCLUDE_DIR}/hoel.h")
    set(regex_hoel_version "^#define[ \t]+HOEL_VERSION[ \t]+([^\"]+).*")
    file(STRINGS "${HOEL_INCLUDE_DIR}/hoel.h" hoel_version REGEX "${regex_hoel_version}")
    string(REGEX REPLACE "${regex_hoel_version}" "\\1" HOEL_VERSION_STRING "${hoel_version}")
    unset(regex_hoel_version)
    unset(hoel_version)
endif ()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Hoel
        REQUIRED_VARS HOEL_LIBRARY HOEL_INCLUDE_DIR
        VERSION_VAR HOEL_VERSION_STRING)

if (HOEL_FOUND)
    set(HOEL_LIBRARIES ${HOEL_LIBRARY})
    set(HOEL_INCLUDE_DIRS ${HOEL_INCLUDE_DIR})
endif ()

mark_as_advanced(HOEL_INCLUDE_DIR HOEL_LIBRARY)
