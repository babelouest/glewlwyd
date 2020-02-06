#.rst:
# FindRhonabwy
# -----------
#
# Find Rhonabwy
#
# Find Rhonabwy headers and libraries.
#
# ::
#
#   RHONABWY_FOUND          - True if Rhonabwy found.
#   RHONABWY_INCLUDE_DIRS   - Where to find rhonabwy.h.
#   RHONABWY_LIBRARIES      - List of libraries when using Rhonabwy.
#   RHONABWY_VERSION_STRING - The version of Rhonabwy found.

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
pkg_check_modules(PC_RHONABWY QUIET librhonabwy)

find_path(RHONABWY_INCLUDE_DIR
        NAMES rhonabwy.h
        HINTS ${PC_RHONABWY_INCLUDEDIR} ${PC_RHONABWY_INCLUDE_DIRS})

find_library(RHONABWY_LIBRARY
        NAMES rhonabwy librhonabwy
        HINTS ${PC_RHONABWY_LIBDIR} ${PC_RHONABWY_LIBRARY_DIRS})

set(RHONABWY_VERSION_STRING 0.0.0)
if (PC_RHONABWY_VERSION)
    set(RHONABWY_VERSION_STRING ${PC_RHONABWY_VERSION})
elseif (RHONABWY_INCLUDE_DIR AND EXISTS "${RHONABWY_INCLUDE_DIR}/rhonabwy.h")
    set(regex_rhonabwy_version "^#define[ \t]+RHONABWY_VERSION[ \t]+([^\"]+).*")
    file(STRINGS "${RHONABWY_INCLUDE_DIR}/rhonabwy.h" rhonabwy_version REGEX "${regex_rhonabwy_version}")
    string(REGEX REPLACE "${regex_rhonabwy_version}" "\\1" RHONABWY_VERSION_STRING "${rhonabwy_version}")
    unset(regex_rhonabwy_version)
    unset(rhonabwy_version)
    if (NOT RHONABWY_VERSION_STRING)
        set(regex_rhonabwy_version "^#define[ \t]+RHONABWY_VERSION[ \t]+([^\"]+).*")
        file(STRINGS "${RHONABWY_INCLUDE_DIR}/rhonabwy-cfg.h" rhonabwy_version REGEX "${regex_rhonabwy_version}")
        string(REGEX REPLACE "${regex_rhonabwy_version}" "\\1" RHONABWY_VERSION_STRING "${rhonabwy_version}")
        unset(regex_rhonabwy_version)
        unset(rhonabwy_version)
    endif()
endif ()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Rhonabwy
        REQUIRED_VARS RHONABWY_LIBRARY RHONABWY_INCLUDE_DIR
        VERSION_VAR RHONABWY_VERSION_STRING)

if (RHONABWY_FOUND)
    set(RHONABWY_LIBRARIES ${RHONABWY_LIBRARY})
    set(RHONABWY_INCLUDE_DIRS ${RHONABWY_INCLUDE_DIR})
endif ()

mark_as_advanced(RHONABWY_INCLUDE_DIR RHONABWY_LIBRARY)
