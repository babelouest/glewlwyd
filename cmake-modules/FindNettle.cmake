#.rst:
# FindNettle
# -----------
#
# Find Nettle
#
# Find Nettle headers and libraries.
#
# ::
#
#   NETTLE_FOUND          - True if Nettle found.
#   NETTLE_INCLUDE_DIRS   - Where to find nettle.h.
#   NETTLE_LIBRARIES      - List of libraries when using Nettle.

#=============================================================================
# Copyright 2019 Nicolas Mora <mail@babelouest.org>
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
pkg_check_modules(PC_NETTLE QUIET nettle)

find_path(NETTLE_INCLUDE_DIR
        NAMES nettle/version.h
        HINTS ${PC_NETTLE_INCLUDEDIR} ${PC_NETTLE_INCLUDE_DIRS})

find_library(NETTLE_LIBRARY
        NAMES nettle libnettle
        HINTS ${PC_NETTLE_LIBDIR} ${PC_NETTLE_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Nettle
        REQUIRED_VARS NETTLE_LIBRARY NETTLE_INCLUDE_DIR)

if (NETTLE_FOUND)
    set(NETTLE_LIBRARIES ${NETTLE_LIBRARY})
    set(NETTLE_INCLUDE_DIRS ${NETTLE_INCLUDE_DIR})
    if (NOT TARGET Nettle::Nettle)
        add_library(Nettle::Nettle UNKNOWN IMPORTED)
        set_target_properties(Nettle::Nettle PROPERTIES
                IMPORTED_LOCATION "${NETTLE_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${NETTLE_INCLUDE_DIR}")
    endif ()
endif ()

mark_as_advanced(NETTLE_INCLUDE_DIR NETTLE_LIBRARY)
