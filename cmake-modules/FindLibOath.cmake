#.rst:
# FindLibOath
# -----------
#
# Find LibOath
#
# Find LibOath headers and libraries.
#
# ::
#
#   LIBOATH_FOUND          - True if LibOath found.
#   LIBOATH_INCLUDE_DIRS   - Where to find oath.h.
#   LIBOATH_LIBRARIES      - List of libraries when using LibOath.

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
pkg_check_modules(PC_LIBOATH QUIET liboath)

find_path(LIBOATH_INCLUDE_DIR
        NAMES liboath/oath.h
        HINTS ${PC_LIBOATH_INCLUDEDIR} ${PC_LIBOATH_INCLUDE_DIRS})

find_library(LIBOATH_LIBRARY
        NAMES oath liboath
        HINTS ${PC_LIBOATH_LIBDIR} ${PC_LIBOATH_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibOath
        REQUIRED_VARS LIBOATH_LIBRARY LIBOATH_INCLUDE_DIR)

if (LIBOATH_FOUND)
    set(LIBOATH_LIBRARIES ${LIBOATH_LIBRARY})
    set(LIBOATH_INCLUDE_DIRS ${LIBOATH_INCLUDE_DIR})
endif ()

mark_as_advanced(LIBOATH_INCLUDE_DIR LIBOATH_LIBRARY)
