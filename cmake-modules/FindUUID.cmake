#.rst:
# FindUUID
# -----------
#
# Find UUID
#
# Find UUID headers and libraries.
#
# ::
#
#   UUID_FOUND          - True if UUID found.
#   UUID_INCLUDE_DIRS   - Where to find jwt.h.
#   UUID_LIBRARIES      - List of libraries when using UUID.

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
pkg_check_modules(PC_UUID QUIET uuid)

find_path(UUID_INCLUDE_DIR
        NAMES uuid.h
        HINTS ${PC_UUID_INCLUDEDIR} ${PC_UUID_INCLUDE_DIRS})

find_library(UUID_LIBRARY
        NAMES uuid
        HINTS ${PC_UUID_LIBDIR} ${PC_UUID_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(UUID
        REQUIRED_VARS UUID_LIBRARY UUID_INCLUDE_DIR)

if (UUID_FOUND)
    set(UUID_LIBRARIES ${UUID_LIBRARY})
    set(UUID_INCLUDE_DIRS ${UUID_INCLUDE_DIR})
endif ()

mark_as_advanced(UUID_INCLUDE_DIR UUID_LIBRARY)
