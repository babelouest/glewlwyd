#.rst:
# FindLdap
# -----------
#
# Find Ldap
#
# Find Ldap headers and libraries.
#
# ::
#
#   LDAP_FOUND          - True if Ldap found.
#   LDAP_INCLUDE_DIRS   - Where to find ldap.h.
#   LDAP_LIBRARIES      - List of libraries when using Ldap.

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
pkg_check_modules(PC_LDAP QUIET ldap)

find_path(LDAP_INCLUDE_DIR
        NAMES ldap.h
        HINTS ${PC_LDAP_INCLUDEDIR} ${PC_LDAP_INCLUDE_DIRS})

find_library(LDAP_LIBRARY
        NAMES ldap libldap
        HINTS ${PC_LDAP_LIBDIR} ${PC_LDAP_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Ldap
        REQUIRED_VARS LDAP_LIBRARY LDAP_INCLUDE_DIR)

if (LDAP_FOUND)
    set(LDAP_LIBRARIES ${LDAP_LIBRARY})
    set(LDAP_INCLUDE_DIRS ${LDAP_INCLUDE_DIR})
endif ()

mark_as_advanced(LDAP_INCLUDE_DIR LDAP_LIBRARY)
