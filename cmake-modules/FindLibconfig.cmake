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

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libconfig
        REQUIRED_VARS LIBCONFIG_LIBRARY LIBCONFIG_INCLUDE_DIR)

if (LIBCONFIG_FOUND)
    set(LIBCONFIG_LIBRARIES ${LIBCONFIG_LIBRARY})
    set(LIBCONFIG_INCLUDE_DIRS ${LIBCONFIG_INCLUDE_DIR})
    if (NOT TARGET LibConfig::LibConfig)
        add_library(LibConfig::LibConfig UNKNOWN IMPORTED)
        set_target_properties(LibConfig::LibConfig PROPERTIES
                IMPORTED_LOCATION "${LIBCONFIG_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${LIBCONFIG_INCLUDE_DIR}")
    endif ()
endif ()

mark_as_advanced(LIBCONFIG_INCLUDE_DIR LIBCONFIG_LIBRARY)
