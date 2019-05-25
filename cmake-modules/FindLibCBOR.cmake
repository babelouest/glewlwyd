#.rst:
# FindLibCBOR
# -----------
#
# Find LibCBOR
#
# Find LibCBOR headers and libraries.
#
# ::
#
#   LIBCBOR_FOUND          - True if LibCBOR found.
#   LIBCBOR_INCLUDE_DIRS   - Where to find cbor.h.
#   LIBCBOR_LIBRARIES      - List of libraries when using LibCBOR.

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
pkg_check_modules(PC_LIBCBOR QUIET libcbor)

find_path(LIBCBOR_INCLUDE_DIR
        NAMES cbor.h
        HINTS ${PC_LIBCBOR_INCLUDEDIR} ${PC_LIBCBOR_INCLUDE_DIRS})

find_library(LIBCBOR_LIBRARY
        NAMES cbor libcbor liblibcbor
        HINTS ${PC_LIBCBOR_LIBDIR} ${PC_LIBCBOR_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibCBOR
        REQUIRED_VARS LIBCBOR_LIBRARY LIBCBOR_INCLUDE_DIR)

if (LIBCBOR_FOUND)
    set(LIBCBOR_LIBRARIES ${LIBCBOR_LIBRARY})
    set(LIBCBOR_INCLUDE_DIRS ${LIBCBOR_INCLUDE_DIR})
endif ()

mark_as_advanced(LIBCBOR_INCLUDE_DIR LIBCBOR_LIBRARY)
