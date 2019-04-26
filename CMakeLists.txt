#
# Glewlwyd
#
# CMake file used to build program
#
# Copyright 2018 Nicolas Mora <mail@babelouest.org>
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
set(PROGRAM_VERSION_MINOR "0")
set(PROGRAM_VERSION_PATCH "0")
set(PROJECT_DESCRIPTION "OAuth2 authentication server providing Json Web Tokens")
set(PROJECT_BUGREPORT_PATH "https://github.com/babelouest/glewlwyd/issues")
set(ORCANIA_VERSION_REQUIRED "2.0.0")
set(YDER_VERSION_REQUIRED "1.4.5")
set(ULFIUS_VERSION_REQUIRED "2.6.0")
set(HOEL_VERSION_REQUIRED "1.4.9")

set(USER_MODULES_SRC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src/user/")
set(USER_MODULES "")

set(CLIENT_MODULES_SRC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src/client/")
set(CLIENT_MODULES "")

set(SCHEME_MODULES_SRC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src/scheme/")
set(SCHEME_MODULES "")

set(PLUGIN_MODULES_SRC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src/plugin/")
set(PLUGIN_MODULES "")

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

set(LIBS "-ldl")

include(FindJansson)
set(JANSSON_MIN_VERSION 2.4)
find_package(Jansson ${JANSSON_MIN_VERSION} REQUIRED)
if (JANSSON_FOUND)
	set(LIBS ${LIBS} ${JANSSON_LIBRARIES})
	include_directories(${JANSSON_INCLUDE_DIRS})
endif ()

include(FindMHD)
set(MHD_MIN_VERSION 0.9.38)
find_package(MHD ${MHD_MIN_VERSION} REQUIRED)
if (MHD_FOUND)
	set(LIBS ${LIBS} ${MHD_LIBRARIES})
	include_directories(${MHD_INCLUDE_DIRS})
endif ()

include(FindGnuTLS)
find_package(GnuTLS REQUIRED)
if (GNUTLS_FOUND)
	set(LIBS ${LIBS} ${GNUTLS_LIBRARIES})
	include_directories(${GNUTLS_INCLUDE_DIRS})
endif ()

include(FindLibconfig)
find_package(Libconfig REQUIRED)
if (LIBCONFIG_FOUND)
	set(LIBS ${LIBS} ${LIBCONFIG_LIBRARIES})
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

set(SEARCH_ORCANIA OFF CACHE BOOL "Force to false") # Avoid to search and download orcania during yder search and download
set(SEARCH_ORCANIA_U OFF CACHE BOOL "Force to false") # Avoid to search and download orcania during ulfius search and download
set(SEARCH_ORCANIA_H OFF CACHE BOOL "Force to false") # Avoid to search and download orcania during hoel search and download
set(SEARCH_YDER OFF CACHE BOOL "Force to false") # Avoid to search and download yder during ulfius and hoel search and download

set(Orcania_FIND_QUIETLY ON) # force to find Orcania quietly
include(FindOrcania)
find_package(Orcania ${ORCANIA_VERSION_REQUIRED} QUIET) # try to find orcania
if (NOT ORCANIA_FOUND)
	include(DownloadProject)
	download_project(PROJ orcania # ... otherwise, download archive
			URL "https://github.com/babelouest/orcania/archive/v${ORCANIA_VERSION_REQUIRED}.tar.gz"
			QUIET)
	add_subdirectory(${orcania_SOURCE_DIR} ${orcania_BINARY_DIR})
	include_directories(${orcania_SOURCE_DIR}/include)
	add_dependencies(glewlwyd orcania)
	set(ORCANIA_LIBRARIES orcania)
	include_directories(${orcania_BINARY_DIR})
endif ()
set(LIBS ${LIBS} ${ORCANIA_LIBRARIES})

set(Yder_FIND_QUIETLY ON) # force to find Yder quietly
include(FindYder)
find_package(Yder ${YDER_VERSION_REQUIRED} QUIET) # try to find Yder
if (NOT YDER_FOUND)
	include(DownloadProject)
	option(CHECK_ORCANIA "specific param" off)
	download_project(PROJ yder # ... otherwise, download archive
			URL "https://github.com/babelouest/yder/archive/v${YDER_VERSION_REQUIRED}.tar.gz"
			QUIET)
	add_subdirectory(${yder_SOURCE_DIR} ${yder_BINARY_DIR})
	include_directories(${yder_SOURCE_DIR}/include)
	include_directories(${orcania_SOURCE_DIR}/include)
	add_dependencies(glewlwyd yder)
	set(YDER_LIBRARIES yder)
	include_directories(${yder_BINARY_DIR})
endif ()
set(LIBS ${LIBS} ${YDER_LIBRARIES})

set(Ulfius_FIND_QUIETLY ON)
include(FindUlfius)
find_package(Ulfius ${ULFIUS_VERSION_REQUIRED} QUIET)
if (NOT ULFIUS_FOUND)
	include(DownloadProject)
	option(WITH_WEBSOCKET "specific param" off)
	option(INSTALL_HEADER "specific param" off)
	option(CHECK_YDER "specific param" off)
	download_project(PROJ ulfius
			URL "https://github.com/babelouest/ulfius/archive/v${ULFIUS_VERSION_REQUIRED}.tar.gz"
			QUIET)
	add_subdirectory(${ulfius_SOURCE_DIR} ${ulfius_BINARY_DIR})
	include_directories(${yder_SOURCE_DIR}/include)
	include_directories(${orcania_SOURCE_DIR}/include)
	include_directories(${ulfius_SOURCE_DIR}/include)
	add_dependencies(glewlwyd ulfius)
	set(ULFIUS_LIBRARIES ulfius)
	include_directories(${ulfius_BINARY_DIR})
endif ()
set(LIBS ${LIBS} ${ULFIUS_LIBRARIES})

set(Hoel_FIND_QUIETLY ON)
include(FindHoel)
find_package(Hoel ${HOEL_VERSION_REQUIRED} QUIET)
if (NOT HOEL_FOUND)
	include(DownloadProject)
	option(INSTALL_HEADER "specific param" off)
	option(CHECK_YDER "specific param" off)
	download_project(PROJ hoel
			URL "https://github.com/babelouest/hoel/archive/v${HOEL_VERSION_REQUIRED}.tar.gz"
			QUIET)
	add_subdirectory(${hoel_SOURCE_DIR} ${hoel_BINARY_DIR})
	include_directories(${hoel_SOURCE_DIR}/include)
	add_dependencies(glewlwyd hoel)
	set(HOEL_LIBRARIES hoel)
	include_directories(${hoel_BINARY_DIR})
endif ()
set(LIBS ${LIBS} ${HOEL_LIBRARIES})

target_link_libraries(glewlwyd ${LIBS})

option(WITH_MOCK "Build Mock modules" off)

# user modules

if (WITH_MOCK OR BUILD_GLEWLWYD_TESTING)
	set(MOCK_LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${USER_MODULES_SRC_PATH}/mock.c)

	set(MOCK_LIBS "-ldl")

	add_library(usermodmock MODULE ${MOCK_LIB_SRC})
	set_target_properties(usermodmock PROPERTIES
			COMPILE_OPTIONS -Wextra)
	target_link_libraries(usermodmock ${MOCK_LIBS})
	set(USER_MODULES ${USER_MODULES} usermodmock)
endif ()

option(WITH_USER_DATABASE "Build Database backend user module" on)
if (WITH_USER_DATABASE)
	set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${USER_MODULES_SRC_PATH}/database.c)

	set(MOD_LIBS "-ldl")

	add_library(usermoddatabase MODULE ${LIB_SRC})
	set_target_properties(usermoddatabase PROPERTIES
			COMPILE_OPTIONS -Wextra)
	target_link_libraries(usermoddatabase ${MOD_LIBS})
	set(USER_MODULES ${USER_MODULES} usermoddatabase)
endif ()

option(WITH_USER_LDAP "Build LDAP backend user module" on)
if (WITH_USER_LDAP)
	include(FindLdap)
	find_package(Ldap REQUIRED)
	if (LDAP_FOUND)
		set(MOD_LIBS ${LDAP_LIBRARIES} "-llber -ldl")
		include_directories(${LDAP_INCLUDE_DIRS})
	endif ()
	set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${USER_MODULES_SRC_PATH}/ldap.c)

	add_library(usermodldap MODULE ${LIB_SRC})
	set_target_properties(usermodldap PROPERTIES
			COMPILE_OPTIONS -Wextra)
	target_link_libraries(usermodldap ${MOD_LIBS})
	set(USER_MODULES ${USER_MODULES} usermodldap)
endif ()

option(WITH_USER_HTTP "Build HTTP backend user module" on)
if (WITH_USER_HTTP)
	set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${USER_MODULES_SRC_PATH}/http.c)

	set(MOD_LIBS "-ldl")

	add_library(usermodhttp MODULE ${LIB_SRC})
	set_target_properties(usermodhttp PROPERTIES
			COMPILE_OPTIONS -Wextra)
	target_link_libraries(usermodhttp ${MOD_LIBS})
	set(USER_MODULES ${USER_MODULES} usermodhttp)
endif ()

# clients modules

if (WITH_MOCK OR BUILD_GLEWLWYD_TESTING)
	set(MOCK_LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${CLIENT_MODULES_SRC_PATH}/mock.c)

	set(MOCK_LIBS "-ldl")

	add_library(clientmodmock MODULE ${MOCK_LIB_SRC})
	set_target_properties(clientmodmock PROPERTIES
			COMPILE_OPTIONS -Wextra)
	target_link_libraries(clientmodmock ${MOCK_LIBS})
	set(CLIENT_MODULES ${CLIENT_MODULES} clientmodmock)
endif ()

option(WITH_CLIENT_DATABASE "Build Database backend client module" on)
if (WITH_CLIENT_DATABASE)
	set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${CLIENT_MODULES_SRC_PATH}/database.c)

	set(MOD_LIBS "-ldl")

	add_library(clientmoddatabase MODULE ${LIB_SRC})
	set_target_properties(clientmoddatabase PROPERTIES
			COMPILE_OPTIONS -Wextra)
	target_link_libraries(clientmoddatabase ${MOD_LIBS})
	set(CLIENT_MODULES ${CLIENT_MODULES} clientmoddatabase)
endif ()

option(WITH_CLIENT_LDAP "Build LDAP backend client module" on)
if (WITH_CLIENT_LDAP)
	include(FindLdap)
	find_package(Ldap REQUIRED)
	if (LDAP_FOUND)
		set(MOD_LIBS ${LDAP_LIBRARIES} "-llber -ldl")
		include_directories(${LDAP_INCLUDE_DIRS})
	endif ()
	set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${CLIENT_MODULES_SRC_PATH}/ldap.c)

	add_library(clientmodldap MODULE ${LIB_SRC})
	set_target_properties(clientmodldap PROPERTIES
			COMPILE_OPTIONS -Wextra)
	target_link_libraries(clientmodldap ${MOD_LIBS})
	set(CLIENT_MODULES ${CLIENT_MODULES} clientmodldap)
endif ()

# schemes modules

if (WITH_MOCK OR BUILD_GLEWLWYD_TESTING)
	set(MOCK_LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${SCHEME_MODULES_SRC_PATH}/mock.c)

	set(MOCK_LIBS "-ldl")

	add_library(schememodmock MODULE ${MOCK_LIB_SRC})
	set_target_properties(schememodmock PROPERTIES
			COMPILE_OPTIONS -Wextra)
	target_link_libraries(schememodmock ${MOCK_LIBS})
	set(SCHEME_MODULES ${SCHEME_MODULES} schememodmock)
endif ()

option(WITH_SCHEME_EMAIL "Build e-mail scheme module" on)
if (WITH_SCHEME_EMAIL)
	set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${SCHEME_MODULES_SRC_PATH}/email.c)

	set(MOD_LIBS "-ldl")

	add_library(schememodemail MODULE ${LIB_SRC})
	set_target_properties(schememodemail PROPERTIES
			COMPILE_OPTIONS -Wextra)
	target_link_libraries(schememodemail ${MOD_LIBS})
	set(CLIENT_MODULES ${CLIENT_MODULES} schememodemail)
endif ()

# plugins modules

if (WITH_MOCK OR BUILD_GLEWLWYD_TESTING)
	set(MOCK_LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${PLUGIN_MODULES_SRC_PATH}/mock.c)

	set(MOCK_LIBS "-ldl")

	add_library(pluginmodmock MODULE ${MOCK_LIB_SRC})
	set_target_properties(pluginmodmock PROPERTIES
			COMPILE_OPTIONS -Wextra)
	target_link_libraries(pluginmodmock ${MOCK_LIBS})
	set(PLUGIN_MODULES ${PLUGIN_MODULES} pluginmodmock)
endif ()

option(WITH_PLUGIN_OAUTH2 "Build legacy oauth2 plugin module" on)
if (WITH_PLUGIN_OAUTH2)
    include(FindLibJWT)
    find_package(LibJWT REQUIRED)
    if (LIBJWT_FOUND)
        set(MOD_LIBS ${LIBJWT_LIBRARIES})
        include_directories(${LIBJWT_INCLUDE_DIRS})
    endif ()
    
	set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${PLUGIN_MODULES_SRC_PATH}/protocol_oauth2.c)

	set(MOD_LIBS "-ldl")

	add_library(protocol_oauth2 MODULE ${LIB_SRC})
	set_target_properties(protocol_oauth2 PROPERTIES
			COMPILE_OPTIONS -Wextra)
	target_link_libraries(protocol_oauth2 ${MOD_LIBS})
	set(CLIENT_MODULES ${CLIENT_MODULES} protocol_oauth2)
endif ()

# tests

option(BUILD_GLEWLWYD_TESTING "Build the testing tree." OFF)

if (BUILD_GLEWLWYD_TESTING)
	include(FindCheck)
	find_package(Check REQUIRED)
	if (CHECK_FOUND)
		include(FindSubunit)
		find_package(Subunit REQUIRED)

		enable_testing()

		set(CMAKE_CTEST_COMMAND ctest -V)

		set(TST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)
		set(LIBS ${LIBS} ${CHECK_LIBRARIES})
		find_package(Threads REQUIRED)
		set(LIBS ${LIBS} ${SUBUNIT_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} m rt)

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
                    glewlwyd_oauth2_refresh_manage 
                    glewlwyd_oauth2_refresh_manage_session
                    glewlwyd_mod_user_http
                    glewlwyd_mod_user_irl
                    glewlwyd_mod_client_irl
                    glewlwyd_oauth2_irl)

		configure_file(
				"${CMAKE_MODULE_PATH}/CTestCustom.cmake.in"
				"${CMAKE_CURRENT_BINARY_DIR}/CTestCustom.cmake"
				@ONLY)

        set(COUNTER 0)
		foreach (t ${TESTS})
			add_executable(${t} EXCLUDE_FROM_ALL ${TST_DIR}/${t}.c ${TST_DIR}/unit-tests.c ${TST_DIR}/unit-tests.h)
			target_include_directories(${t} PUBLIC ${TST_DIR})
			target_link_libraries(${t} PUBLIC ${LIBS})
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
            endif ()
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
install(TARGETS ${USER_MODULES}
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/glewlwyd/user)
install(TARGETS ${CLIENT_MODULES}
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/glewlwyd/client)
install(TARGETS ${SCHEME_MODULES}
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/glewlwyd/scheme)
install(TARGETS ${PLUGIN_MODULES}
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/glewlwyd/plugin)
install(DIRECTORY docs/database/
	DESTINATION ${CMAKE_INSTALL_DOCDIR}/database/ COMPONENT runtime)
install(FILES README.md
	DESTINATION ${CMAKE_INSTALL_DOCDIR}/ COMPONENT runtime)
install(FILES docs/API.md
	DESTINATION ${CMAKE_INSTALL_DOCDIR}/ COMPONENT runtime)
install(FILES docs/INSTALL.md
	DESTINATION ${CMAKE_INSTALL_DOCDIR}/ COMPONENT runtime)
install(FILES docs/glewlwyd.service
	DESTINATION ${CMAKE_INSTALL_DOCDIR}/ COMPONENT runtime)
install(FILES docs/glewlwyd-init
	DESTINATION ${CMAKE_INSTALL_DOCDIR}/ COMPONENT runtime)

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
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.3.4), libconfig9, libgnutls30 (>= 3.5.0), libjansson4 (>= 2.7), libldap-2.4-2 (>= 2.4.7), liborcania (>= ${ORCANIA_VERSION_REQUIRED}), libyder (>= ${YDER_VERSION_REQUIRED}), libulfius (>= ${ULFIUS_VERSION_REQUIRED}), libhoel (>= ${HOEL_VERSION_REQUIRED}), lsb-base (>= 3.0-6)")
set(CPACK_PACKAGE_FILE_NAME ${PACKAGE_FILE_NAME})

set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_PACKAGE_FILE_NAME ${PACKAGE_FILE_NAME})
set(CPACK_SOURCE_IGNORE_FILES ${PACKAGE_IGNORED_FILES})

include(CPack)

add_custom_target(dist_g
	COMMAND ${CMAKE_MAKE_PROGRAM} package_source)
