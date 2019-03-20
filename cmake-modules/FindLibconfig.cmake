#.rst:
# FindLibconfig
# -----------
#
# Find Libconfig
#
# Find Libconfig headers and libraries.
#
# ::
#
#   LIBCONFIG_FOUND          - True if Libconfig found.
#   LIBCONFIG_INCLUDE_DIRS   - Where to find jwt.h.
#   LIBCONFIG_LIBRARIES      - List of libraries when using Libconfig.

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
pkg_check_modules(PC_LIBCONFIG QUIET libconfig)

find_path(LIBCONFIG_INCLUDE_DIR
        NAMES libconfig.h
        HINTS ${PC_LIBCONFIG_INCLUDEDIR} ${PC_LIBCONFIG_INCLUDE_DIRS})

find_library(LIBCONFIG_LIBRARY
        NAMES libconfig config
        HINTS ${PC_LIBCONFIG_LIBDIR} ${PC_LIBCONFIG_LIBRARY_DIRS})

if (PC_LIBCONFIG_VERSION)
    set(LIBCONFIG_VERSION_STRING ${PC_LIBCONFIG_VERSION})
elseif (LIBCONFIG_INCLUDE_DIR AND EXISTS "${LIBCONFIG_INCLUDE_DIR}/libconfig.h")
    set(libconfig_version_list MAJOR MINOR REVISION)
    foreach (v ${libconfig_version_list})
        set(regex_libconfig_version "^#define LIBCONFIG_${v}_VERSION +\\(?([0-9]+)\\)?$")
        file(STRINGS "${LIBCONFIG_INCLUDE_DIR}/libconfig.h" libconfig_version_${v} REGEX "${regex_libconfig_version}")
        string(REGEX REPLACE "${regex_libconfig_version}" "\\1" libconfig_version_${v} "${libconfig_version_${v}}")
        unset(regex_libconfig_version)
    endforeach ()
    set(LIBCONFIG_VERSION_STRING "${libconfig_version_MAJOR}.${libconfig_version_MINOR}.${libconfig_version_REVISION}")
    foreach (v libconfig_version_list)
        unset(libconfig_version_${v})
    endforeach ()
    unset(libconfig_version_list)
endif ()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libconfig
        REQUIRED_VARS LIBCONFIG_LIBRARY LIBCONFIG_INCLUDE_DIR
        VERSION_VAR LIBCONFIG_VERSION_STRING)

if (LIBCONFIG_FOUND)
    set(LIBCONFIG_LIBRARIES ${LIBCONFIG_LIBRARY})
    set(LIBCONFIG_INCLUDE_DIRS ${LIBCONFIG_INCLUDE_DIR})
endif ()

mark_as_advanced(LIBCONFIG_INCLUDE_DIR LIBCONFIG_LIBRARY)
