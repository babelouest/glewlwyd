#.rst:
# FindLibJWT
# -----------
#
# Find LibJWT
#
# Find LibJWT headers and libraries.
#
# ::
#
#   LIBJWT_FOUND          - True if LibJWT found.
#   LIBJWT_INCLUDE_DIRS   - Where to find jwt.h.
#   LIBJWT_LIBRARIES      - List of libraries when using LibJWT.

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
pkg_check_modules(PC_LIBJWT QUIET libjwt)

find_path(LIBJWT_INCLUDE_DIR
        NAMES jwt.h
        HINTS ${PC_LIBJWT_INCLUDEDIR} ${PC_LIBJWT_INCLUDE_DIRS})

find_library(LIBJWT_LIBRARY
        NAMES jwt libjwt liblibjwt
        HINTS ${PC_LIBJWT_LIBDIR} ${PC_LIBJWT_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibJWT
        REQUIRED_VARS LIBJWT_LIBRARY LIBJWT_INCLUDE_DIR)

if (LIBJWT_FOUND)
    set(LIBJWT_LIBRARIES ${LIBJWT_LIBRARY})
    set(LIBJWT_INCLUDE_DIRS ${LIBJWT_INCLUDE_DIR})
endif ()

mark_as_advanced(LIBJWT_INCLUDE_DIR LIBJWT_LIBRARY)
