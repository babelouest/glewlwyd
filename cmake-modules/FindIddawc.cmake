#.rst:
# FindIddawc
# -----------
#
# Find Iddawc
#
# Find Iddawc headers and libraries.
#
# ::
#
#   IDDAWC_FOUND          - True if Iddawc found.
#   IDDAWC_INCLUDE_DIRS   - Where to find iddawc.h.
#   IDDAWC_LIBRARIES      - List of libraries when using Iddawc.
#   IDDAWC_VERSION_STRING - The version of Iddawc found.

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
pkg_check_modules(PC_IDDAWC QUIET libiddawc)

find_path(IDDAWC_INCLUDE_DIR
        NAMES iddawc.h
        HINTS ${PC_IDDAWC_INCLUDEDIR} ${PC_IDDAWC_INCLUDE_DIRS})

find_library(IDDAWC_LIBRARY
        NAMES iddawc libiddawc
        HINTS ${PC_IDDAWC_LIBDIR} ${PC_IDDAWC_LIBRARY_DIRS})

set(IDDAWC_VERSION_STRING 0.0.0)
if (PC_IDDAWC_VERSION)
    set(IDDAWC_VERSION_STRING ${PC_IDDAWC_VERSION})
elseif (IDDAWC_INCLUDE_DIR AND EXISTS "${IDDAWC_INCLUDE_DIR}/iddawc.h")
    set(regex_iddawc_version "^#define[ \t]+IDDAWC_VERSION[ \t]+([^\"]+).*")
    file(STRINGS "${IDDAWC_INCLUDE_DIR}/iddawc.h" iddawc_version REGEX "${regex_iddawc_version}")
    string(REGEX REPLACE "${regex_iddawc_version}" "\\1" IDDAWC_VERSION_STRING "${iddawc_version}")
    unset(regex_iddawc_version)
    unset(iddawc_version)
    if (NOT IDDAWC_VERSION_STRING)
        set(regex_iddawc_version "^#define[ \t]+IDDAWC_VERSION[ \t]+([^\"]+).*")
        file(STRINGS "${IDDAWC_INCLUDE_DIR}/iddawc-cfg.h" iddawc_version REGEX "${regex_iddawc_version}")
        string(REGEX REPLACE "${regex_iddawc_version}" "\\1" IDDAWC_VERSION_STRING "${iddawc_version}")
        unset(regex_iddawc_version)
        unset(iddawc_version)
    endif()
endif ()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Iddawc
        REQUIRED_VARS IDDAWC_LIBRARY IDDAWC_INCLUDE_DIR
        VERSION_VAR IDDAWC_VERSION_STRING)

if (PC_IDDAWC_FOUND)
    set(IDDAWC_FOUND 1)
endif ()

if (IDDAWC_FOUND)
    set(IDDAWC_LIBRARIES ${IDDAWC_LIBRARY})
    set(IDDAWC_INCLUDE_DIRS ${IDDAWC_INCLUDE_DIR})
endif ()

mark_as_advanced(IDDAWC_INCLUDE_DIR IDDAWC_LIBRARY)
