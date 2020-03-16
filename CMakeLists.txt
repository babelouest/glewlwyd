#
# Glewlwyd
#
# CMake file used to build program
#
# Copyright 2016-2020 Nicolas Mora <mail@babelouest.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the MIT License
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#

cmake_minimum_required(VERSION 3.5)

project(glewlwyd C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")

# library info

set(PROGRAM_VERSION_MAJOR "2")
set(PROGRAM_VERSION_MINOR "2")
set(PROGRAM_VERSION_PATCH "0")
set(PROJECT_DESCRIPTION "Single Sign On server, OAuth2, multiple factor authentication with, HOTP/TOTP, Webauthn, etc. extensible via plugins")
set(PROJECT_BUGREPORT_PATH "https://github.com/babelouest/glewlwyd/issues")
set(ORCANIA_VERSION_REQUIRED "2.1.0")
set(YDER_VERSION_REQUIRED "1.4.10")
set(ULFIUS_VERSION_REQUIRED "2.6.5")
set(HOEL_VERSION_REQUIRED "1.4.14")
set(RHONABWY_VERSION_REQUIRED "0.9.5")
set(IDDAWC_VERSION_REQUIRED "0.9.4")
set(LIBJWT_VERSION_REQUIRED "1.10.0")
set(LIBCBOR_VERSION_REQUIRED "0.5.0")
set(JANSSON_VERSION_REQUIRED "2.11")

set(USER_MODULES_SRC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src/user/")
set(USER_MODULES "")

set(CLIENT_MODULES_SRC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src/client/")
set(CLIENT_MODULES "")

set(SCHEME_MODULES_SRC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src/scheme/")
set(SCHEME_MODULES "")

set(PLUGIN_MODULES_SRC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src/plugin/")
set(PLUGIN_MODULES "")

set(RESOURCES_SRC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/docs/resources/ulfius/")

include(GNUInstallDirs)
include(CheckSymbolExists)

# cmake modules

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake-modules)

# check if _GNU_SOURCE is available

if (NOT _GNU_SOURCE)
	check_symbol_exists(__GNU_LIBRARY__ "features.h" _GNU_SOURCE)

	if (NOT _GNU_SOURCE)
		unset(_GNU_SOURCE CACHE)
		check_symbol_exists(_GNU_SOURCE "features.h" _GNU_SOURCE)
	endif ()
endif ()

if (_GNU_SOURCE)
	add_definitions(-D_GNU_SOURCE)
endif ()

set(GLWD_LIBS "-ldl")

find_package(Threads REQUIRED)
set(GLWD_LIBS ${GLWD_LIBS} ${CMAKE_THREAD_LIBS_INIT})

include(FindJansson)
find_package(Jansson ${JANSSON_VERSION_REQUIRED} REQUIRED)
if (JANSSON_FOUND)
	set(GLWD_LIBS ${GLWD_LIBS} ${JANSSON_LIBRARIES})
	include_directories(${JANSSON_INCLUDE_DIRS})
endif ()

include(FindGnuTLS)
find_package(GnuTLS REQUIRED)
if (GNUTLS_FOUND)
	set(GLWD_LIBS ${GLWD_LIBS} ${GNUTLS_LIBRARIES})
	include_directories(${GNUTLS_INCLUDE_DIRS})
endif ()

include(FindNettle)
find_package(Nettle REQUIRED)
if (NETTLE_FOUND)
	set(GLWD_LIBS ${GLWD_LIBS} ${NETTLE_LIBRARIES})
	include_directories(${NETTLE_INCLUDE_DIRS})
endif ()

include(FindLibconfig)
find_package(Libconfig REQUIRED)
if (LIBCONFIG_FOUND)
	set(GLWD_LIBS ${GLWD_LIBS} ${LIBCONFIG_LIBRARIES})
	include_directories(${LIBCONFIG_INCLUDE_DIRS})
endif ()

# build

add_executable(glewlwyd ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd.h
				${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h
				${CMAKE_CURRENT_SOURCE_DIR}/src/static_file_callback.h
				${CMAKE_CURRENT_SOURCE_DIR}/src/client.c
				${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c
				${CMAKE_CURRENT_SOURCE_DIR}/src/module.c
				${CMAKE_CURRENT_SOURCE_DIR}/src/plugin.c
				${CMAKE_CURRENT_SOURCE_DIR}/src/scope.c
				${CMAKE_CURRENT_SOURCE_DIR}/src/session.c
				${CMAKE_CURRENT_SOURCE_DIR}/src/static_file_callback.c
				${CMAKE_CURRENT_SOURCE_DIR}/src/user.c
				${CMAKE_CURRENT_SOURCE_DIR}/src/webservice.c
				${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd.c )

set(SEARCH_ORCANIA OFF CACHE BOOL "Force to false") # Avoid to search and download orcania during orcania search and download
set(SEARCH_YDER OFF CACHE BOOL "Force to false") # Avoid to search and download yder during ulfius and hoel search and download

set(SEARCH_ORCANIA_U OFF CACHE BOOL "Force to false") # Avoid to search and download orcania during ulfius search and download

set(SEARCH_ORCANIA_H OFF CACHE BOOL "Force to false") # Avoid to search and download orcania during hoel search and download

set(SEARCH_ORCANIA_R OFF CACHE BOOL "Force to false") # Avoid to search and download orcania during hoel search and download
set(SEARCH_YDER_R OFF CACHE BOOL "Force to false") # Avoid to search and download yder during ulfius and hoel search and download
set(SEARCH_ULFIUS_R OFF CACHE BOOL "Force to false") # Avoid to search and download ulfius during rhonabwy search and download

set(SEARCH_ORCANIA_I OFF CACHE BOOL "Force to false") # Avoid to search and download orcania during iddawc search and download
set(SEARCH_YDER_I OFF CACHE BOOL "Force to false") # Avoid to search and download yder during iddawc search and download
set(SEARCH_ULFIUS_I OFF CACHE BOOL "Force to false") # Avoid to search and download ulfius during iddawc search and download
set(SEARCH_RHONABWY_I OFF CACHE BOOL "Force to false") # Avoid to search and download rhonabwy during iddawc search and download

option(DOWNLOAD_DEPENDENCIES "Download required dependencies" ON)

set(Orcania_FIND_QUIETLY ON) # force to find Orcania quietly
include(FindOrcania)
find_package(Orcania ${ORCANIA_VERSION_REQUIRED} QUIET) # try to find orcania
if (ORCANIA_FOUND)
	include_directories(${orcania_SOURCE_DIR}/include)
elseif (NOT ORCANIA_FOUND AND DOWNLOAD_DEPENDENCIES)
	include(DownloadProject)
	message(STATUS "Download Orcania ${ORCANIA_VERSION_REQUIRED}")
	download_project(PROJ orcania # ... otherwise, download archive
			URL "https://github.com/babelouest/orcania/archive/v${ORCANIA_VERSION_REQUIRED}.tar.gz"
			QUIET)
	add_subdirectory(${orcania_SOURCE_DIR} ${orcania_BINARY_DIR})
	include_directories(${orcania_SOURCE_DIR}/include)
	add_dependencies(glewlwyd orcania)
	set(ORCANIA_LIBRARIES orcania)
	include_directories(${orcania_BINARY_DIR})
else ()
	message( FATAL_ERROR "Orcania not found")
endif ()
set(GLWD_LIBS ${GLWD_LIBS} ${ORCANIA_LIBRARIES})

set(Yder_FIND_QUIETLY ON) # force to find Yder quietly
include(FindYder)
find_package(Yder ${YDER_VERSION_REQUIRED} QUIET) # try to find Yder
if (YDER_FOUND)
	include_directories(${yder_SOURCE_DIR}/include)
elseif (NOT YDER_FOUND AND DOWNLOAD_DEPENDENCIES)
	include(DownloadProject)
	message(STATUS "Download Yder ${YDER_VERSION_REQUIRED}")
	option(CHECK_ORCANIA "specific param" off)
	download_project(PROJ yder # ... otherwise, download archive
			URL "https://github.com/babelouest/yder/archive/v${YDER_VERSION_REQUIRED}.tar.gz"
			QUIET)
	add_subdirectory(${yder_SOURCE_DIR} ${yder_BINARY_DIR})
	include_directories(${yder_SOURCE_DIR}/include)
	include_directories(${orcania_SOURCE_DIR}/include)
	add_dependencies(glewlwyd yder)
	add_dependencies(yder orcania)
	set(YDER_LIBRARIES yder)
	include_directories(${yder_BINARY_DIR})
else ()
	message( FATAL_ERROR "Yder not found")
endif ()
set(GLWD_LIBS ${GLWD_LIBS} ${YDER_LIBRARIES})

set(Ulfius_FIND_QUIETLY ON)
include(FindUlfius)
find_package(Ulfius ${ULFIUS_VERSION_REQUIRED} QUIET)
if (ULFIUS_FOUND)
	include_directories(${ulfius_SOURCE_DIR}/include)
elseif (NOT ULFIUS_FOUND AND DOWNLOAD_DEPENDENCIES)
	include(DownloadProject)
	option(WITH_WEBSOCKET "specific param" off)
	option(INSTALL_HEADER "specific param" off)
	option(CHECK_YDER "specific param" off)
	message(STATUS "Download Ulfius ${ULFIUS_VERSION_REQUIRED}")
	download_project(PROJ ulfius
			URL "https://github.com/babelouest/ulfius/archive/v${ULFIUS_VERSION_REQUIRED}.tar.gz"
			QUIET)
	add_subdirectory(${ulfius_SOURCE_DIR} ${ulfius_BINARY_DIR})
	include_directories(${yder_SOURCE_DIR}/include)
	include_directories(${orcania_SOURCE_DIR}/include)
	include_directories(${ulfius_SOURCE_DIR}/include)
	add_dependencies(glewlwyd ulfius)
	add_dependencies(ulfius yder)
	add_dependencies(ulfius orcania)
	set(ULFIUS_LIBRARIES ulfius)
	include_directories(${ulfius_BINARY_DIR})
else ()
	message( FATAL_ERROR "Ulfius not found")
endif ()
set(GLWD_LIBS ${GLWD_LIBS} ${ULFIUS_LIBRARIES})

set(Hoel_FIND_QUIETLY ON)
include(FindHoel)
find_package(Hoel ${HOEL_VERSION_REQUIRED} QUIET)
if (HOEL_FOUND)
	include_directories(${hoel_SOURCE_DIR}/include)
elseif (NOT HOEL_FOUND AND DOWNLOAD_DEPENDENCIES)
	include(DownloadProject)
	option(INSTALL_HEADER "specific param" off)
	option(CHECK_YDER "specific param" off)
	message(STATUS "Download Hoel ${HOEL_VERSION_REQUIRED}")
	download_project(PROJ hoel
			URL "https://github.com/babelouest/hoel/archive/v${HOEL_VERSION_REQUIRED}.tar.gz"
			QUIET)
	add_subdirectory(${hoel_SOURCE_DIR} ${hoel_BINARY_DIR})
	include_directories(${hoel_SOURCE_DIR}/include)
	add_dependencies(glewlwyd hoel)
	add_dependencies(hoel yder)
	add_dependencies(hoel orcania)
	set(HOEL_LIBRARIES hoel)
	include_directories(${hoel_BINARY_DIR})
else ()
	message( FATAL_ERROR "Hoel not found")
endif ()
set(GLWD_LIBS ${GLWD_LIBS} ${HOEL_LIBRARIES})

target_link_libraries(glewlwyd ${GLWD_LIBS})

set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.3.4)")

execute_process(COMMAND lsb_release -is
		OUTPUT_VARIABLE DISTRIB_CODENAME_T
		OUTPUT_STRIP_TRAILING_WHITESPACE
)
string( TOLOWER "${DISTRIB_CODENAME_T}" DISTRIB_CODENAME )

execute_process(COMMAND lsb_release -cs
		OUTPUT_VARIABLE RELEASE_CODENAME_T
		OUTPUT_STRIP_TRAILING_WHITESPACE
)
string( TOLOWER "${RELEASE_CODENAME_T}" RELEASE_CODENAME )

option(WITH_MOCK "Build Mock modules" off)

# user modules

if (WITH_MOCK OR BUILD_GLEWLWYD_TESTING)
	set(MOCK_LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${USER_MODULES_SRC_PATH}/mock.c)

	add_library(usermodmock MODULE ${MOCK_LIB_SRC})
	set_target_properties(usermodmock PROPERTIES
			COMPILE_OPTIONS -Wextra
			LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/user")
	target_link_libraries(usermodmock ${GLWD_LIBS})
	set(USER_MODULES ${USER_MODULES} usermodmock)
endif ()

option(WITH_USER_DATABASE "Build Database backend user module" on)
if (WITH_USER_DATABASE)
	set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${USER_MODULES_SRC_PATH}/database.c)

	add_library(usermoddatabase MODULE ${LIB_SRC})
	set_target_properties(usermoddatabase PROPERTIES
			COMPILE_OPTIONS -Wextra
			LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/user")
	target_link_libraries(usermoddatabase ${GLWD_LIBS})
	set(USER_MODULES ${USER_MODULES} usermoddatabase)
endif ()

option(WITH_USER_LDAP "Build LDAP backend user module" on)
if (WITH_USER_LDAP)
	include(FindLdap)
	find_package(Ldap REQUIRED)
	if (LDAP_FOUND)
		include_directories(${LDAP_INCLUDE_DIRS})
	endif ()
	set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${USER_MODULES_SRC_PATH}/ldap.c)
	set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libldap-2.4-2 (>= 2.4.7)")

	add_library(usermodldap MODULE ${LIB_SRC})
	set_target_properties(usermodldap PROPERTIES
			COMPILE_OPTIONS -Wextra
			LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/user")
	target_link_libraries(usermodldap ${GLWD_LIBS} ${LDAP_LIBRARIES} "-llber")
	set(USER_MODULES ${USER_MODULES} usermodldap)
endif ()

option(WITH_USER_HTTP "Build HTTP backend user module" on)
if (WITH_USER_HTTP)
	set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${USER_MODULES_SRC_PATH}/http.c)

	add_library(usermodhttp MODULE ${LIB_SRC})
	set_target_properties(usermodhttp PROPERTIES
			COMPILE_OPTIONS -Wextra
			LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/user")
	target_link_libraries(usermodhttp ${GLWD_LIBS})
	set(USER_MODULES ${USER_MODULES} usermodhttp)
endif ()

# clients modules

if (WITH_MOCK OR BUILD_GLEWLWYD_TESTING)
	set(MOCK_LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${CLIENT_MODULES_SRC_PATH}/mock.c)

	add_library(clientmodmock MODULE ${MOCK_LIB_SRC})
	set_target_properties(clientmodmock PROPERTIES
			COMPILE_OPTIONS -Wextra
			LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/client")
	target_link_libraries(clientmodmock ${GLWD_LIBS})
	set(CLIENT_MODULES ${CLIENT_MODULES} clientmodmock)
endif ()

option(WITH_CLIENT_DATABASE "Build Database backend client module" on)
if (WITH_CLIENT_DATABASE)
	set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${CLIENT_MODULES_SRC_PATH}/database.c)

	add_library(clientmoddatabase MODULE ${LIB_SRC})
	set_target_properties(clientmoddatabase PROPERTIES
			COMPILE_OPTIONS -Wextra
			LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/client")
	target_link_libraries(clientmoddatabase ${GLWD_LIBS})
	set(CLIENT_MODULES ${CLIENT_MODULES} clientmoddatabase)
endif ()

option(WITH_CLIENT_LDAP "Build LDAP backend client module" on)
if (WITH_CLIENT_LDAP)
	include(FindLdap)
	find_package(Ldap REQUIRED)
	if (LDAP_FOUND)
		include_directories(${LDAP_INCLUDE_DIRS})
	endif ()
	set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${CLIENT_MODULES_SRC_PATH}/ldap.c)
	set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libldap-2.4-2 (>= 2.4.7)")

	add_library(clientmodldap MODULE ${LIB_SRC})
	set_target_properties(clientmodldap PROPERTIES
			COMPILE_OPTIONS -Wextra
			LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/client")
	target_link_libraries(clientmodldap ${GLWD_LIBS} ${LDAP_LIBRARIES} "-llber")
	set(CLIENT_MODULES ${CLIENT_MODULES} clientmodldap)
endif ()

# schemes modules

if (WITH_MOCK OR BUILD_GLEWLWYD_TESTING)
	set(MOCK_LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${SCHEME_MODULES_SRC_PATH}/mock.c)

	set(MOCK_LIBS ${ULFIUS_LIBRARIES} "-ldl")

	add_library(schememodmock MODULE ${MOCK_LIB_SRC})
	set_target_properties(schememodmock PROPERTIES
			COMPILE_OPTIONS -Wextra
			LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/scheme")
	target_link_libraries(schememodmock ${GLWD_LIBS})
	set(SCHEME_MODULES ${SCHEME_MODULES} schememodmock)
endif ()

option(WITH_SCHEME_RETYPE_PASSWORD "Build retype password scheme module" on)
if (WITH_SCHEME_RETYPE_PASSWORD)
	set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${SCHEME_MODULES_SRC_PATH}/password.c)

	add_library(schememodpassword MODULE ${LIB_SRC})
	set_target_properties(schememodpassword PROPERTIES
			COMPILE_OPTIONS -Wextra
			LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/scheme")
	target_link_libraries(schememodpassword ${GLWD_LIBS})
	set(SCHEME_MODULES ${SCHEME_MODULES} schememodpassword)
endif ()

option(WITH_SCHEME_EMAIL "Build e-mail scheme module" on)
if (WITH_SCHEME_EMAIL)
	set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${SCHEME_MODULES_SRC_PATH}/email.c)

	add_library(schememodemail MODULE ${LIB_SRC})
	set_target_properties(schememodemail PROPERTIES
			COMPILE_OPTIONS -Wextra
			LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/scheme")
	target_link_libraries(schememodemail ${GLWD_LIBS})
	set(SCHEME_MODULES ${SCHEME_MODULES} schememodemail)
endif ()

option(WITH_SCHEME_OTP "Build OTP scheme module" on)
if (WITH_SCHEME_OTP)
	include(FindLibOath)
	find_package(LibOath REQUIRED)
	if (LIBOATH_FOUND)
			include_directories(${LIBOATH_INCLUDE_DIR})
	endif ()
	
	set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${SCHEME_MODULES_SRC_PATH}/otp.c)
	set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, liboath0 (>= 2.6.0)")

	add_library(schememodotp MODULE ${LIB_SRC})
	set_target_properties(schememodotp PROPERTIES
			COMPILE_OPTIONS -Wextra
			LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/scheme")
	target_link_libraries(schememodotp ${GLWD_LIBS} ${LIBOATH_LIBRARIES})
	set(SCHEME_MODULES ${SCHEME_MODULES} schememodotp)
endif ()

option(WITH_SCHEME_WEBAUTHN "Build Webauthn scheme module" on)
if (WITH_SCHEME_WEBAUTHN)
	include(FindLibJWT)
	find_package(LibJWT ${LIBJWT_VERSION_REQUIRED} REQUIRED)
	if (LIBJWT_FOUND)
			include_directories(${LIBJWT_INCLUDE_DIRS})
	endif ()
	
	include(FindLibCBOR)
	find_package(LibCBOR REQUIRED)
	if (LIBCBOR_FOUND)
			include_directories(${LIBCBOR_INCLUDE_DIRS})
	endif ()

	include(FindLdap)
	find_package(Ldap REQUIRED)
	if (LDAP_FOUND)
		include_directories(${LDAP_INCLUDE_DIRS})
	endif ()
	
	set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${SCHEME_MODULES_SRC_PATH}/webauthn.c)

	if (NOT ${RELEASE_CODENAME} STREQUAL "stretch" AND NOT ${RELEASE_CODENAME} STREQUAL "bionic")
		set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libjwt0 (>= ${LIBJWT_VERSION_REQUIRED})")
	endif ()
	if (NOT ${RELEASE_CODENAME} STREQUAL "stretch")
		set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libcbor0")
	endif ()

	set(Rhonabwy_FIND_QUIETLY ON) # force to find Rhonabwy quietly
	include(FindRhonabwy)
	find_package(Rhonabwy ${RHONABWY_VERSION_REQUIRED} QUIET) # try to find rhonabwy
	if (RHONABWY_FOUND)
		include_directories(${rhonabwy_SOURCE_DIR}/include)
	elseif (NOT RHONABWY_FOUND AND DOWNLOAD_DEPENDENCIES)
		include(DownloadProject)
		message(STATUS "Download Rhonabwy ${RHONABWY_VERSION_REQUIRED}")
		download_project(PROJ rhonabwy # ... otherwise, download archive
				URL "https://github.com/babelouest/rhonabwy/archive/v${RHONABWY_VERSION_REQUIRED}.tar.gz"
				QUIET)
		add_subdirectory(${rhonabwy_SOURCE_DIR} ${rhonabwy_BINARY_DIR})
		include_directories(${rhonabwy_SOURCE_DIR}/include)
		set(RHONABWY_LIBRARIES rhonabwy)
		include_directories(${rhonabwy_BINARY_DIR})
		set (RHONABWY_FOUND ON)
	else ()
		message( FATAL_ERROR "Rhonabwy not found")
	endif ()

	add_library(schememodwebauthn MODULE ${LIB_SRC})
	set_target_properties(schememodwebauthn PROPERTIES
			COMPILE_OPTIONS -Wextra
			LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/scheme")
	target_link_libraries(schememodwebauthn ${GLWD_LIBS} ${LIBJWT_LIBRARIES} ${LIBCBOR_LIBRARIES} ${LDAP_LIBRARIES} ${RHONABWY_LIBRARIES})
	set(SCHEME_MODULES ${SCHEME_MODULES} schememodwebauthn)
endif ()

option(WITH_SCHEME_CERTIFICATE "Build certificate scheme module" on)
if (WITH_SCHEME_CERTIFICATE)
	set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${SCHEME_MODULES_SRC_PATH}/certificate.c)

	add_library(schememodcertificate MODULE ${LIB_SRC})
	set_target_properties(schememodcertificate PROPERTIES
			COMPILE_OPTIONS -Wextra
			LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/scheme")
	target_link_libraries(schememodcertificate ${GLWD_LIBS})
	set(SCHEME_MODULES ${SCHEME_MODULES} schememodcertificate)
endif ()

option(WITH_SCHEME_HTTP "Build HTTP Basic Auth scheme module" on)
if (WITH_SCHEME_HTTP)
	set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${SCHEME_MODULES_SRC_PATH}/http.c)

	add_library(schememodhttp MODULE ${LIB_SRC})
	set_target_properties(schememodhttp PROPERTIES
			COMPILE_OPTIONS -Wextra)
	target_link_libraries(schememodhttp ${GLWD_LIBS})
	set(SCHEME_MODULES ${SCHEME_MODULES} schememodhttp)
endif ()

option(WITH_SCHEME_OAUTH2 "Build Oauth2/OIDC scheme module" on)
if (WITH_SCHEME_OAUTH2)
	include(FindLibJWT)
	find_package(LibJWT ${LIBJWT_VERSION_REQUIRED} REQUIRED)
	if (LIBJWT_FOUND)
			include_directories(${LIBJWT_INCLUDE_DIRS})
	endif ()
	
	set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${SCHEME_MODULES_SRC_PATH}/oauth2.c)

	if (NOT ${RELEASE_CODENAME} STREQUAL "stretch" AND NOT ${RELEASE_CODENAME} STREQUAL "bionic")
		set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libjwt0 (>= ${LIBJWT_VERSION_REQUIRED})")
	endif ()

	if (NOT RHONABWY_FOUND)
		set(Rhonabwy_FIND_QUIETLY ON) # force to find Rhonabwy quietly
		include(FindRhonabwy)
		find_package(Rhonabwy ${RHONABWY_VERSION_REQUIRED} QUIET) # try to find rhonabwy
		if (RHONABWY_FOUND)
			include_directories(${rhonabwy_SOURCE_DIR}/include)
		elseif (NOT RHONABWY_FOUND AND DOWNLOAD_DEPENDENCIES)
			include(DownloadProject)
			message(STATUS "Download Rhonabwy ${RHONABWY_VERSION_REQUIRED}")
			download_project(PROJ rhonabwy # ... otherwise, download archive
					URL "https://github.com/babelouest/rhonabwy/archive/v${RHONABWY_VERSION_REQUIRED}.tar.gz"
					QUIET)
			add_subdirectory(${rhonabwy_SOURCE_DIR} ${rhonabwy_BINARY_DIR})
			include_directories(${rhonabwy_SOURCE_DIR}/include)
			set(RHONABWY_LIBRARIES rhonabwy)
			include_directories(${rhonabwy_BINARY_DIR})
			set (RHONABWY_FOUND ON)
			add_dependencies(rhonabwy orcania)
			add_dependencies(rhonabwy yder)
			add_dependencies(rhonabwy ulfius)
		else ()
			message( FATAL_ERROR "Rhonabwy not found")
		endif ()
	endif ()

	set(Iddawc_FIND_QUIETLY ON) # force to find Iddawc quietly
	include(FindIddawc)
	find_package(Iddawc ${IDDAWC_VERSION_REQUIRED} QUIET) # try to find iddawc
	if (IDDAWC_FOUND)
		include_directories(${iddawc_SOURCE_DIR}/include)
	elseif (NOT IDDAWC_FOUND AND DOWNLOAD_DEPENDENCIES)
		include(DownloadProject)
		message(STATUS "Download Iddawc ${IDDAWC_VERSION_REQUIRED}")
		download_project(PROJ iddawc # ... otherwise, download archive
				URL "https://github.com/babelouest/iddawc/archive/v${IDDAWC_VERSION_REQUIRED}.tar.gz"
				QUIET)
		add_subdirectory(${iddawc_SOURCE_DIR} ${iddawc_BINARY_DIR})
		include_directories(${iddawc_SOURCE_DIR}/include)
		set(IDDAWC_LIBRARIES iddawc)
		include_directories(${iddawc_BINARY_DIR})
		set (IDDAWC_FOUND ON)
		add_dependencies(iddawc orcania)
		add_dependencies(iddawc yder)
		add_dependencies(iddawc ulfius)
		add_dependencies(iddawc rhonabwy)
	else ()
		message( FATAL_ERROR "Iddawc not found")
	endif ()

	add_library(schememodoauth2 MODULE ${LIB_SRC})
	set_target_properties(schememodoauth2 PROPERTIES
			COMPILE_OPTIONS -Wextra
			LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/scheme")
	target_link_libraries(schememodoauth2 ${GLWD_LIBS} ${LIBJWT_LIBRARIES} ${RHONABWY_LIBRARIES} ${IDDAWC_LIBRARIES})
	set(SCHEME_MODULES ${SCHEME_MODULES} schememodoauth2)
endif ()

# plugins modules

if (WITH_MOCK OR BUILD_GLEWLWYD_TESTING)
	set(MOCK_LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${PLUGIN_MODULES_SRC_PATH}/mock.c)

	set(MOCK_LIBS "-ldl")

	add_library(pluginmodmock MODULE ${MOCK_LIB_SRC})
	set_target_properties(pluginmodmock PROPERTIES
			COMPILE_OPTIONS -Wextra
			LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugin")
	target_link_libraries(pluginmodmock ${MOCK_LIBS})
	set(PLUGIN_MODULES ${PLUGIN_MODULES} pluginmodmock)
endif ()

option(WITH_PLUGIN_OAUTH2 "Build legacy oauth2 plugin module" on)
if (WITH_PLUGIN_OAUTH2)
		include(FindLibJWT)
		find_package(LibJWT ${LIBJWT_VERSION_REQUIRED} REQUIRED)
		if (LIBJWT_FOUND)
				include_directories(${LIBJWT_INCLUDE_DIRS})
		endif ()
		
	set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${PLUGIN_MODULES_SRC_PATH}/protocol_oauth2.c ${RESOURCES_SRC_PATH}/glewlwyd_resource.c ${RESOURCES_SRC_PATH}/glewlwyd_resource.h)
	if (NOT ${RELEASE_CODENAME} STREQUAL "stretch" AND NOT ${RELEASE_CODENAME} STREQUAL "bionic")
		set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libjwt0 (>= ${LIBJWT_VERSION_REQUIRED})")
	endif ()

	add_library(protocol_oauth2 MODULE ${LIB_SRC})
	set_target_properties(protocol_oauth2 PROPERTIES
			COMPILE_OPTIONS -Wextra
			LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugin")
	target_link_libraries(protocol_oauth2 ${GLWD_LIBS} ${LIBJWT_LIBRARIES})
	set(PLUGIN_MODULES ${PLUGIN_MODULES} protocol_oauth2)
endif ()

option(WITH_PLUGIN_OIDC "Build OpenID Connect plugin module" on)
if (WITH_PLUGIN_OIDC)
	include(FindLibJWT)
	find_package(LibJWT ${LIBJWT_VERSION_REQUIRED} REQUIRED)
	if (LIBJWT_FOUND)
			include_directories(${LIBJWT_INCLUDE_DIRS})
	endif ()

	if (NOT RHONABWY_FOUND)
		set(Rhonabwy_FIND_QUIETLY ON) # force to find Rhonabwy quietly
		include(FindRhonabwy)
		find_package(Rhonabwy ${RHONABWY_VERSION_REQUIRED} QUIET) # try to find rhonabwy
		if (RHONABWY_FOUND)
			include_directories(${rhonabwy_SOURCE_DIR}/include)
		elseif (NOT RHONABWY_FOUND AND DOWNLOAD_DEPENDENCIES)
			include(DownloadProject)
			message(STATUS "Download Rhonabwy ${RHONABWY_VERSION_REQUIRED}")
			download_project(PROJ rhonabwy # ... otherwise, download archive
					URL "https://github.com/babelouest/rhonabwy/archive/v${RHONABWY_VERSION_REQUIRED}.tar.gz"
					QUIET)
			add_subdirectory(${rhonabwy_SOURCE_DIR} ${rhonabwy_BINARY_DIR})
			include_directories(${rhonabwy_SOURCE_DIR}/include)
			set(RHONABWY_LIBRARIES rhonabwy)
			include_directories(${rhonabwy_BINARY_DIR})
			set (RHONABWY_FOUND ON)
		else ()
			message( FATAL_ERROR "Rhonabwy not found")
		endif ()
	endif ()

	set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${PLUGIN_MODULES_SRC_PATH}/protocol_oidc.c ${RESOURCES_SRC_PATH}/oidc_resource.c ${RESOURCES_SRC_PATH}/oidc_resource.h)
	if (NOT ${RELEASE_CODENAME} STREQUAL "stretch" AND NOT ${RELEASE_CODENAME} STREQUAL "bionic")
		set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libjwt0 (>= ${LIBJWT_VERSION_REQUIRED})")
	endif ()

	add_library(protocol_oidc MODULE ${LIB_SRC})
	set_target_properties(protocol_oidc PROPERTIES
			COMPILE_OPTIONS -Wextra
			LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugin")
	target_link_libraries(protocol_oidc ${GLWD_LIBS} ${LIBJWT_LIBRARIES} ${RHONABWY_LIBRARIES})
	set(PLUGIN_MODULES ${PLUGIN_MODULES} protocol_oidc)
endif ()

option(WITH_PLUGIN_REGISTER "Build register plugin module" on)
if (WITH_PLUGIN_REGISTER)
		
	set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${PLUGIN_MODULES_SRC_PATH}/register.c)

	add_library(protocol_register MODULE ${LIB_SRC})
	set_target_properties(protocol_register PROPERTIES
			COMPILE_OPTIONS -Wextra
			LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugin")
	target_link_libraries(protocol_register ${GLWD_LIBS})
	set(PLUGIN_MODULES ${PLUGIN_MODULES} protocol_register)
endif ()

# tests

option(BUILD_GLEWLWYD_TESTING "Build the testing tree" OFF)

if (BUILD_GLEWLWYD_TESTING)
	include(FindCheck)
	find_package(Check REQUIRED)
	if (CHECK_FOUND)
		include(FindSubunit)
		find_package(Subunit REQUIRED)

		enable_testing()

		set(CMAKE_CTEST_COMMAND ctest -V)

		set(TST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)
		find_package(Threads REQUIRED)
		
		set(TST_LIBS ${TST_LIBS} ${JANSSON_LIBRARIES})
		set(TST_LIBS ${TST_LIBS} ${ORCANIA_LIBRARIES})
		set(TST_LIBS ${TST_LIBS} ${YDER_LIBRARIES})
		set(TST_LIBS ${TST_LIBS} ${ULFIUS_LIBRARIES})
		set(TST_LIBS ${TST_LIBS} ${RHONABWY_LIBRARIES})
		set(TST_LIBS ${TST_LIBS} ${GNUTLS_LIBRARIES})
		set(TST_LIBS ${TST_LIBS} ${LIBJWT_LIBRARIES})
		set(TST_LIBS ${TST_LIBS} ${CHECK_LIBRARIES} ${SUBUNIT_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} m rt)

		set(TESTS glewlwyd_admin_mod_type 
							glewlwyd_admin_mod_user 
							glewlwyd_admin_mod_user_auth_scheme 
							glewlwyd_admin_mod_client 
							glewlwyd_admin_mod_plugin 
							glewlwyd_auth_password 
							glewlwyd_auth_scheme 
							glewlwyd_auth_grant 
							glewlwyd_auth_check_scheme 
							glewlwyd_auth_scheme_trigger 
							glewlwyd_auth_scheme_register 
							glewlwyd_auth_profile 
							glewlwyd_auth_session_manage 
							glewlwyd_auth_profile_get_scheme_available
							glewlwyd_crud_user
							glewlwyd_crud_client
							glewlwyd_crud_scope 
							glewlwyd_mod_user_http
							glewlwyd_mod_user_irl
							glewlwyd_mod_client_irl
							glewlwyd_profile_delete
							)

		if (WITH_PLUGIN_OAUTH2)
			set (TST_LIBS ${TST_LIBS} ${LIBJWT_LIBRARIES} ${GNUTLS_LIBRARIES})
			set (TESTS ${TESTS}
							glewlwyd_oauth2_additional_parameters
							glewlwyd_oauth2_auth_code 
							glewlwyd_oauth2_code 
							glewlwyd_oauth2_code_client_confidential 
							glewlwyd_oauth2_implicit 
							glewlwyd_oauth2_resource_owner_pwd_cred 
							glewlwyd_oauth2_resource_owner_pwd_cred_client_confidential 
							glewlwyd_oauth2_client_cred 
							glewlwyd_oauth2_refresh_token 
							glewlwyd_oauth2_refresh_token_client_confidential 
							glewlwyd_oauth2_delete_token 
							glewlwyd_oauth2_delete_token_client_confidential 
							glewlwyd_oauth2_profile 
							glewlwyd_oauth2_profile_impersonate
							glewlwyd_oauth2_refresh_manage 
							glewlwyd_oauth2_refresh_manage_session
							glewlwyd_oauth2_irl
							glewlwyd_oauth2_code_challenge
							glewlwyd_oauth2_token_introspection
							glewlwyd_oauth2_token_revocation
							)
		endif ()
		
		if (WITH_PLUGIN_OIDC)
			set (TST_LIBS ${TST_LIBS} ${LIBJWT_LIBRARIES} ${GNUTLS_LIBRARIES})
			set (TESTS ${TESTS}
							glewlwyd_oidc_additional_parameters
							glewlwyd_oidc_auth_code
							glewlwyd_oidc_client_cred
							glewlwyd_oidc_code
							glewlwyd_oidc_code_client_confidential
							glewlwyd_oidc_code_idtoken
							glewlwyd_oidc_delete_token
							glewlwyd_oidc_delete_token_client_confidential
							glewlwyd_oidc_hybrid_id_token_code
							glewlwyd_oidc_hybrid_id_token_token_code
							glewlwyd_oidc_hybrid_token_code
							glewlwyd_oidc_implicit_id_token
							glewlwyd_oidc_implicit_id_token_token
							glewlwyd_oidc_irl
							glewlwyd_oidc_only_no_refresh
							glewlwyd_oidc_optional_request_parameters
							glewlwyd_oidc_refresh_manage
							glewlwyd_oidc_refresh_manage_session
							glewlwyd_oidc_refresh_token
							glewlwyd_oidc_refresh_token_client_confidential
							glewlwyd_oidc_resource_owner_pwd_cred
							glewlwyd_oidc_resource_owner_pwd_cred_client_confidential
							glewlwyd_oidc_token
							glewlwyd_oidc_userinfo
              glewlwyd_oidc_discovery
              glewlwyd_oidc_client_secret
              glewlwyd_oidc_request_jwt
              glewlwyd_oidc_subject_type
              glewlwyd_oidc_address_claim
              glewlwyd_oidc_claims_scopes
              glewlwyd_oidc_claim_request
              glewlwyd_oidc_code_challenge
							glewlwyd_oidc_token_introspection
							glewlwyd_oidc_token_revocation
							glewlwyd_oidc_client_registration
							)
		endif ()

		if (WITH_PLUGIN_REGISTER)
			set (TESTS ${TESTS}
							glewlwyd_register
							)
		endif ()
		
		if (WITH_SCHEME_OTP)
			set (TST_LIBS ${TST_LIBS} ${LIBOATH_LIBRARIES})
			set (TESTS ${TESTS} glewlwyd_scheme_otp)
		endif ()

		if (WITH_SCHEME_WEBAUTHN)
			set(TST_LIBS ${TST_LIBS} ${LIBCBOR_LIBRARIES})
			set (TESTS ${TESTS} glewlwyd_scheme_webauthn)
		endif ()

		if (WITH_SCHEME_EMAIL)
			set (TESTS ${TESTS} glewlwyd_scheme_mail)
		endif ()

		if (WITH_SCHEME_RETYPE_PASSWORD)
			set (TESTS ${TESTS} glewlwyd_scheme_retype_password)
		endif ()

		if (WITH_SCHEME_HTTP)
			set(TESTS ${TESTS} glewlwyd_scheme_http)
		endif ()

		if (WITH_SCHEME_OAUTH2)
			set(TST_LIBS ${TST_LIBS} ${IDDAWC_LIBRARIES})
			set(TESTS ${TESTS} glewlwyd_scheme_oauth2)
		endif ()

		if (WITH_SCHEME_CERTIFICATE)
			set(TESTS_SSL glewlwyd_scheme_certificate)
		endif ()

		configure_file(
				"${CMAKE_MODULE_PATH}/CTestCustom.cmake.in"
				"${CMAKE_CURRENT_BINARY_DIR}/CTestCustom.cmake"
				@ONLY)

				set(COUNTER 0)
		foreach (t ${TESTS})
			add_executable(${t} EXCLUDE_FROM_ALL ${TST_DIR}/${t}.c ${TST_DIR}/unit-tests.c ${TST_DIR}/unit-tests.h)
			target_include_directories(${t} PUBLIC ${TST_DIR})
			target_link_libraries(${t} PUBLIC ${TST_LIBS})
			if (NOT ${t} MATCHES "_irl$")
				add_test(NAME ${t}
								WORKING_DIRECTORY ${TST_DIR}
								COMMAND ${t})
			elseif (${t} MATCHES "_user_irl$")
				FILE(GLOB UserJsonIrl ${TST_DIR}/mod_user_*.json)
				foreach (j ${UserJsonIrl})
						add_test(NAME "${t}_${COUNTER}"
										WORKING_DIRECTORY ${TST_DIR}
										COMMAND ${t} ${j})
						MATH(EXPR COUNTER "${COUNTER}+1")
				endforeach ()
			elseif (${t} MATCHES "_client_irl$")
				FILE(GLOB UserJsonIrl ${TST_DIR}/mod_client_*.json)
				foreach (j ${UserJsonIrl})
						add_test(NAME "${t}_${COUNTER}"
										WORKING_DIRECTORY ${TST_DIR}
										COMMAND ${t} ${j})
						MATH(EXPR COUNTER "${COUNTER}+1")
				endforeach ()
			elseif (${t} MATCHES "_oauth2_irl$")
				FILE(GLOB UserJsonIrl ${TST_DIR}/plugin_oauth2_*.json)
				foreach (j ${UserJsonIrl})
						add_test(NAME "${t}_${COUNTER}"
										WORKING_DIRECTORY ${TST_DIR}
										COMMAND ${t} ${j})
						MATH(EXPR COUNTER "${COUNTER}+1")
				endforeach ()
			elseif (${t} MATCHES "_oidc_irl$")
				FILE(GLOB UserJsonIrl ${TST_DIR}/plugin_iodc_*.json)
				foreach (j ${UserJsonIrl})
						add_test(NAME "${t}_${COUNTER}"
										WORKING_DIRECTORY ${TST_DIR}
										COMMAND ${t} ${j})
						MATH(EXPR COUNTER "${COUNTER}+1")
				endforeach ()
			endif ()
		endforeach ()
		
		foreach (t ${TESTS_SSL})
			add_executable(${t} EXCLUDE_FROM_ALL ${TST_DIR}/${t}.c ${TST_DIR}/unit-tests.c ${TST_DIR}/unit-tests.h)
			target_include_directories(${t} PUBLIC ${TST_DIR})
			target_link_libraries(${t} PUBLIC ${TST_LIBS})
		endforeach ()
				
	endif ()
endif ()

# install target

install(TARGETS glewlwyd
		RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES docs/glewlwyd.conf.sample
		DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/glewlwyd RENAME glewlwyd.conf COMPONENT config)
install(DIRECTORY webapp/
		DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/glewlwyd/webapp/ COMPONENT runtime)
install(FILES webapp/config.json.sample
		DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/glewlwyd/webapp/ RENAME config.json COMPONENT runtime)
install(TARGETS ${USER_MODULES}
		DESTINATION ${CMAKE_INSTALL_LIBDIR}/glewlwyd/user)
install(TARGETS ${CLIENT_MODULES}
		DESTINATION ${CMAKE_INSTALL_LIBDIR}/glewlwyd/client)
install(TARGETS ${SCHEME_MODULES}
		DESTINATION ${CMAKE_INSTALL_LIBDIR}/glewlwyd/scheme)
install(TARGETS ${PLUGIN_MODULES}
		DESTINATION ${CMAKE_INSTALL_LIBDIR}/glewlwyd/plugin)
install(DIRECTORY docs/database/
		DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/database/ COMPONENT runtime)
install(FILES README.md
		DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/ COMPONENT runtime)
install(FILES CHANGELOG.md
		DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/ COMPONENT runtime)
install(FILES docs/API.md
		DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/CERTIFICATE.md
		DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/CLIENT_DATABASE.md
		DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/CLIENT_LDAP.md
		DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/GETTING_STARTED.md
		DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/INSTALL.md
		DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/OAUTH2.md
		DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/OIDC.md
		DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/OTP.md
		DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/README.md
		DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/SCOPE.md
		DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/USER_DATABASE.md
		DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/USER_HTTP.md
		DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/USER_LDAP.md
		DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/USER.md
		DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/WEBAUTHN.md
		DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/glewlwyd.service
		DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/glewlwyd-init
		DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)

set(TARGETS glewlwyd)

install(TARGETS ${TARGETS}
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	CONFIGURATIONS Release)

# uninstall target

if (NOT TARGET uninstall)
	configure_file(
		"${CMAKE_MODULE_PATH}/CMakeUninstall.cmake.in"
		"${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
		IMMEDIATE @ONLY)
	add_custom_target(uninstall
			COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif ()

# packaging

set(CPACK_PACKAGE_VERSION_MAJOR ${PROGRAM_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROGRAM_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROGRAM_VERSION_PATCH})

set(PACKAGE_FILE_NAME
		"${CMAKE_PROJECT_NAME}_${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")

set(PACKAGE_IGNORED_FILES
		"${CMAKE_CURRENT_BINARY_DIR}/;/.git/;.gitignore;~$;${CPACK_SOURCE_IGNORE_FILES}")

set(CPACK_GENERATOR "TGZ;DEB")

set(CPACK_DEBIAN_PACKAGE_MAINTAINER "mail@babelouest.org")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION ${PROJECT_DESCRIPTION})
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://github.com/babelouest/glewlwyd")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libconfig9, libgnutls30 (>= 3.5.0), liborcania|liborcania-dev (>= ${ORCANIA_VERSION_REQUIRED}), libyder|libyder-dev (>= ${YDER_VERSION_REQUIRED}), libulfius|libulfius-dev (>= ${ULFIUS_VERSION_REQUIRED}), libhoel|libhoel-dev (>= ${HOEL_VERSION_REQUIRED}), lsb-base (>= 3.0-6)")
set(CPACK_PACKAGE_FILE_NAME ${PACKAGE_FILE_NAME})

if (NOT ${RELEASE_CODENAME} STREQUAL "stretch" AND NOT ${RELEASE_CODENAME} STREQUAL "bionic")
	set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libjansson4 (>= ${JANSSON_VERSION_REQUIRED})")
endif ()

option(BUILD_RPM "Build a RPM for your system" OFF)
if (BUILD_RPM)
  set(CPACK_GENERATOR "TGZ;DEB;RPM")
  set(CPACK_RPM_PACKAGE_LICENSE "GPL")
  set(CPACK_RPM_PACKAGE_URL "http://babelouest.github.io/glewlwyd/")
  set(CPACK_RPM_PACKAGE_REQUIRES "openldap, liboath, libconfig, gnutls >= 3.5.0, jansson >= ${JANSSON_VERSION_REQUIRED}, liborcania >= ${ORCANIA_VERSION_REQUIRED}, libyder >= ${YDER_VERSION_REQUIRED}, libulfius >= ${ULFIUS_VERSION_REQUIRED}, libhoel >= ${HOEL_VERSION_REQUIRED}")
endif ()

set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_PACKAGE_FILE_NAME ${PACKAGE_FILE_NAME})
set(CPACK_SOURCE_IGNORE_FILES ${PACKAGE_IGNORED_FILES})

include(CPack)

add_custom_target(dist_g
	COMMAND ${CMAKE_MAKE_PROGRAM} package_source)

message(STATUS "Download required dependencies:       ${DOWNLOAD_DEPENDENCIES}")
message(STATUS "Build Mock modules:                   ${WITH_MOCK}")
message(STATUS "Build backend user module Database:   ${WITH_USER_DATABASE}")
message(STATUS "Build backend user module LDAP:       ${WITH_USER_LDAP}")
message(STATUS "Build backend user module HTTP:       ${WITH_USER_HTTP}")
message(STATUS "Build backend client module Database: ${WITH_CLIENT_DATABASE}")
message(STATUS "Build backend client module LDAP:     ${WITH_CLIENT_LDAP}")
message(STATUS "Build scheme module retype password:  ${WITH_SCHEME_RETYPE_PASSWORD}")
message(STATUS "Build scheme module e-mail code:      ${WITH_SCHEME_EMAIL}")
message(STATUS "Build scheme module OTP:              ${WITH_SCHEME_OTP}")
message(STATUS "Build scheme module Webauthn:         ${WITH_SCHEME_WEBAUTHN}")
message(STATUS "Build scheme module TLS Certificate:  ${WITH_SCHEME_CERTIFICATE}")
message(STATUS "Build scheme module HTTP:             ${WITH_SCHEME_HTTP}")
message(STATUS "Build scheme module OAuth2:           ${WITH_SCHEME_OAUTH2}")
message(STATUS "Build plugin module legacy oauth2:    ${WITH_PLUGIN_OAUTH2}")
message(STATUS "Build plugin module OpenID Connect:   ${WITH_PLUGIN_OIDC}")
message(STATUS "Build plugin register new account:    ${WITH_PLUGIN_REGISTER}")
message(STATUS "Build the testing tree:               ${BUILD_GLEWLWYD_TESTING}")
message(STATUS "Build RPM package:                    ${BUILD_RPM}")
