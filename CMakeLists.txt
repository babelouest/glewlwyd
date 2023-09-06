#
# Glewlwyd
#
# CMake file used to build program
#
# Copyright 2016-2022 Nicolas Mora <mail@babelouest.org>
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

set(GLWD_LIBS )
set(SCHEME_MODULES )

set(PROGRAM_VERSION_MAJOR "2")
set(PROGRAM_VERSION_MINOR "7")
set(PROGRAM_VERSION_PATCH "6")
set(PROJECT_DESCRIPTION "Single Sign On server, OAuth2, Openid Connect, multiple factor authentication with, HOTP/TOTP, FIDO2, TLS Certificates, etc. extensible via plugins ")
set(PROJECT_BUGREPORT_PATH "https://github.com/babelouest/glewlwyd/issues")
set(LIBCBOR_VERSION_REQUIRED "0.5.0")
set(JANSSON_VERSION_REQUIRED "2.11")
set(ORCANIA_VERSION_REQUIRED "2.3.3")
set(YDER_VERSION_REQUIRED "1.4.19")
set(ULFIUS_VERSION_REQUIRED "2.7.14")
set(HOEL_VERSION_REQUIRED "1.4.28")
set(RHONABWY_VERSION_REQUIRED "1.1.12")
set(IDDAWC_VERSION_REQUIRED "1.1.9")

set(USER_MODULES_SRC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src/user/")
set(USER_MODULES )

set(USER_MIDDLEWARE_MODULES_SRC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src/user_middleware/")
set(USER_MIDDLEWARE_MODULES )

set(CLIENT_MODULES_SRC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src/client/")
set(CLIENT_MODULES )

set(SCHEME_MODULES_SRC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src/scheme/")
set(SCHEME_MODULES )

set(PLUGIN_MODULES_SRC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src/plugin/")
set(PLUGIN_MODULES )

set(RESOURCES_SRC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/docs/resources/ulfius/")

include(GNUInstallDirs)
include(CheckSymbolExists)

# cmake modules

set(G_CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake-modules)
list(APPEND CMAKE_MODULE_PATH "${G_CMAKE_MODULE_PATH}")

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

list(APPEND GLWD_LIBS "-ldl -lcrypt")

find_package(Threads REQUIRED)
list(APPEND GLWD_LIBS ${CMAKE_THREAD_LIBS_INIT})

include(FindJansson)
set(JANSSON_MIN_VERSION 2.4)
find_package(Jansson ${JANSSON_MIN_VERSION} REQUIRED)
list(APPEND GLWD_LIBS Jansson::Jansson)

include(FindNettle)
find_package(Nettle REQUIRED)
list(APPEND GLWD_LIBS Nettle::Nettle)

include(FindGnuTLS)
find_package(GnuTLS REQUIRED)
list(APPEND GLWD_LIBS GnuTLS::GnuTLS)

include(FindMHD)
find_package(MHD REQUIRED)
list(APPEND GLWD_LIBS MHD::MHD)

include(FindLibconfig)
find_package(Libconfig REQUIRED)
list(APPEND GLWD_LIBS LibConfig::LibConfig)

find_package(ZLIB REQUIRED)
list(APPEND GLWD_LIBS ZLIB::ZLIB)

# build

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)
add_executable(glewlwyd ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd.h
                        ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h
                        ${CMAKE_CURRENT_SOURCE_DIR}/src/static_compressed_inmemory_website_callback.h
                        ${CMAKE_CURRENT_SOURCE_DIR}/src/http_compression_callback.h
                        ${CMAKE_CURRENT_SOURCE_DIR}/src/client.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/src/module.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/src/plugin.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/src/scope.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/src/session.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/src/static_compressed_inmemory_website_callback.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/src/http_compression_callback.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/src/user.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/src/api_key.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/src/misc_config.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/src/metrics.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/src/webservice.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd.c )
set_target_properties(glewlwyd PROPERTIES COMPILE_OPTIONS "-Wextra;-Wconversion")

find_package(Orcania ${ORCANIA_VERSION_REQUIRED} REQUIRED)
if ("${ORCANIA_VERSION_STRING}" VERSION_GREATER_EQUAL "${ORCANIA_VERSION_REQUIRED}")
    message(STATUS "Orcania found: ${ORCANIA_VERSION_STRING}")
else ()
    message( FATAL_ERROR "Orcania version required: ${ORCANIA_VERSION_REQUIRED} - version installed: ${ORCANIA_VERSION_STRING}")
endif ()
list(APPEND GLWD_LIBS Orcania::Orcania)

find_package(Yder ${YDER_VERSION_REQUIRED} REQUIRED)
if ("${YDER_VERSION_STRING}" VERSION_GREATER_EQUAL "${YDER_VERSION_REQUIRED}")
    message(STATUS "Yder found: ${YDER_VERSION_STRING}")
else ()
    message( FATAL_ERROR "Yder version required: ${YDER_VERSION_REQUIRED} - version installed: ${YDER_VERSION_STRING}")
endif ()
list(APPEND GLWD_LIBS Yder::Yder)

find_package(Ulfius ${ULFIUS_VERSION_REQUIRED} REQUIRED)
if ("${ULFIUS_VERSION_STRING}" VERSION_GREATER_EQUAL "${ULFIUS_VERSION_REQUIRED}")
    message(STATUS "Ulfius found: ${ULFIUS_VERSION_STRING}")
else ()
    message( FATAL_ERROR "Ulfius version required: ${ULFIUS_VERSION_REQUIRED} - version installed: ${ULFIUS_VERSION_STRING}")
endif ()
list(APPEND GLWD_LIBS Ulfius::Ulfius)

find_package(Hoel ${HOEL_VERSION_REQUIRED} REQUIRED)
if ("${HOEL_VERSION_STRING}" VERSION_GREATER_EQUAL "${HOEL_VERSION_REQUIRED}")
    message(STATUS "Hoel found: ${HOEL_VERSION_STRING}")
else ()
    message( FATAL_ERROR "Hoel version required: ${HOEL_VERSION_REQUIRED} - version installed: ${HOEL_VERSION_STRING}")
endif ()
list(APPEND GLWD_LIBS Hoel::Hoel)

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
      COMPILE_OPTIONS "-Wextra;-Wconversion"
      LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/user")
  target_link_libraries(usermodmock ${GLWD_LIBS})
  list(APPEND USER_MODULES usermodmock)
endif ()

option(WITH_USER_DATABASE "Build Database backend user module" on)
if (WITH_USER_DATABASE)
  set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${USER_MODULES_SRC_PATH}/database.c)

  add_library(usermoddatabase MODULE ${LIB_SRC})
  set_target_properties(usermoddatabase PROPERTIES
      COMPILE_OPTIONS "-Wextra;-Wconversion"
      LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/user")
  target_link_libraries(usermoddatabase ${GLWD_LIBS})
  list(APPEND USER_MODULES usermoddatabase)
endif ()

option(WITH_USER_LDAP "Build LDAP backend user module" on)
if (WITH_USER_LDAP)
  include(FindLdap)
  find_package(Ldap REQUIRED)
  if (LDAP_FOUND)
    include_directories(${LDAP_INCLUDE_DIRS})
  endif ()
  set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${USER_MODULES_SRC_PATH}/ldap.c)
  if ("${DISTRIB_CODENAME}" STREQUAL "ubuntu" AND "${RELEASE_CODENAME}" STREQUAL "impish")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libldap-2.5-0")
  elseif ("${DISTRIB_CODENAME}" STREQUAL "ubuntu" AND "${RELEASE_CODENAME}" STREQUAL "jammy")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libldap-2.5-0")
  elseif ("${DISTRIB_CODENAME}" STREQUAL "ubuntu" AND "${RELEASE_CODENAME}" STREQUAL "kinetic")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libldap-2.5-0")
  elseif ("${DISTRIB_CODENAME}" STREQUAL "debian" AND "${RELEASE_CODENAME}" STREQUAL "bookworm")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libldap-2.5-0")
  else ()
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libldap-2.4-2")
  endif ()

  add_library(usermodldap MODULE ${LIB_SRC})
  set_target_properties(usermodldap PROPERTIES
      COMPILE_OPTIONS "-Wextra;-Wconversion"
      LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/user")
  target_link_libraries(usermodldap ${GLWD_LIBS} OpenLDAP::OpenLDAP "-llber")
  list(APPEND USER_MODULES usermodldap)
endif ()

option(WITH_USER_HTTP "Build HTTP backend user module" on)
if (WITH_USER_HTTP)
  set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${USER_MODULES_SRC_PATH}/http.c)

  add_library(usermodhttp MODULE ${LIB_SRC})
  set_target_properties(usermodhttp PROPERTIES
      COMPILE_OPTIONS "-Wextra;-Wconversion"
      LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/user")
  target_link_libraries(usermodhttp ${GLWD_LIBS})
  list(APPEND USER_MODULES usermodhttp)
endif ()

# user middleware modules

if (WITH_MOCK OR BUILD_GLEWLWYD_TESTING)
  set(MOCK_LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${USER_MIDDLEWARE_MODULES_SRC_PATH}/mock.c)

  add_library(usermidmodmock MODULE ${MOCK_LIB_SRC})
  set_target_properties(usermidmodmock PROPERTIES
      COMPILE_OPTIONS "-Wextra;-Wconversion"
      LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/user_middleware")
  target_link_libraries(usermidmodmock ${GLWD_LIBS})
  set(USER_MIDDLEWARE_MODULES ${USER_MIDDLEWARE_MODULES} usermidmodmock)
endif ()

# clients modules

if (WITH_MOCK OR BUILD_GLEWLWYD_TESTING)
  set(MOCK_LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${CLIENT_MODULES_SRC_PATH}/mock.c)

  add_library(clientmodmock MODULE ${MOCK_LIB_SRC})
  set_target_properties(clientmodmock PROPERTIES
      COMPILE_OPTIONS "-Wextra;-Wconversion"
      LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/client")
  target_link_libraries(clientmodmock ${GLWD_LIBS})
  set(CLIENT_MODULES ${CLIENT_MODULES} clientmodmock)
endif ()

option(WITH_CLIENT_DATABASE "Build Database backend client module" on)
if (WITH_CLIENT_DATABASE)
  set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${CLIENT_MODULES_SRC_PATH}/database.c)

  add_library(clientmoddatabase MODULE ${LIB_SRC})
  set_target_properties(clientmoddatabase PROPERTIES
      COMPILE_OPTIONS "-Wextra;-Wconversion"
      LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/client")
  target_link_libraries(clientmoddatabase ${GLWD_LIBS})
  list(APPEND CLIENT_MODULES clientmoddatabase)
endif ()

option(WITH_CLIENT_LDAP "Build LDAP backend client module" on)
if (WITH_CLIENT_LDAP)
  include(FindLdap)
  find_package(Ldap REQUIRED)
  if (LDAP_FOUND)
    include_directories(${LDAP_INCLUDE_DIRS})
  endif ()
  set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${CLIENT_MODULES_SRC_PATH}/ldap.c)
  if ("${DISTRIB_CODENAME}" STREQUAL "ubuntu" AND "${RELEASE_CODENAME}" STREQUAL "impish")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libldap-2.5-0")
  elseif ("${DISTRIB_CODENAME}" STREQUAL "ubuntu" AND "${RELEASE_CODENAME}" STREQUAL "jammy")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libldap-2.5-0")
  elseif ("${DISTRIB_CODENAME}" STREQUAL "ubuntu" AND "${RELEASE_CODENAME}" STREQUAL "kinetic")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libldap-2.5-0")
  elseif ("${DISTRIB_CODENAME}" STREQUAL "debian" AND "${RELEASE_CODENAME}" STREQUAL "bookworm")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libldap-2.5-0")
  else ()
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libldap-2.4-2")
  endif ()

  add_library(clientmodldap MODULE ${LIB_SRC})
  set_target_properties(clientmodldap PROPERTIES
      COMPILE_OPTIONS "-Wextra;-Wconversion"
      LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/client")
  target_link_libraries(clientmodldap ${GLWD_LIBS} OpenLDAP::OpenLDAP "-llber")
  list(APPEND CLIENT_MODULES clientmodldap)
endif ()

# schemes modules

if (WITH_MOCK OR BUILD_GLEWLWYD_TESTING)
  set(MOCK_LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${SCHEME_MODULES_SRC_PATH}/mock.c)

  set(MOCK_LIBS ${ULFIUS_LIBRARIES} "-ldl")

  add_library(schememodmock MODULE ${MOCK_LIB_SRC})
  set_target_properties(schememodmock PROPERTIES
      COMPILE_OPTIONS "-Wextra;-Wconversion"
      LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/scheme")
  target_link_libraries(schememodmock ${GLWD_LIBS})
  list(APPEND SCHEME_MODULES schememodmock)
endif ()

option(WITH_SCHEME_RETYPE_PASSWORD "Build retype password scheme module" on)
if (WITH_SCHEME_RETYPE_PASSWORD)
  set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${SCHEME_MODULES_SRC_PATH}/password.c)

  add_library(schememodpassword MODULE ${LIB_SRC})
  set_target_properties(schememodpassword PROPERTIES
      COMPILE_OPTIONS "-Wextra;-Wconversion"
      LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/scheme")
  target_link_libraries(schememodpassword ${GLWD_LIBS})
  list(APPEND SCHEME_MODULES schememodpassword)
endif ()

option(WITH_SCHEME_EMAIL "Build e-mail scheme module" on)
if (WITH_SCHEME_EMAIL)
  set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${SCHEME_MODULES_SRC_PATH}/email.c)

  add_library(schememodemail MODULE ${LIB_SRC})
  set_target_properties(schememodemail PROPERTIES
      COMPILE_OPTIONS "-Wextra;-Wconversion"
      LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/scheme")
  target_link_libraries(schememodemail ${GLWD_LIBS})
  list(APPEND SCHEME_MODULES schememodemail)
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
      COMPILE_OPTIONS "-Wextra;-Wconversion"
      LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/scheme")
  target_link_libraries(schememodotp ${GLWD_LIBS} OATH::OATH)
  list(APPEND SCHEME_MODULES schememodotp)
endif ()

option(WITH_SCHEME_WEBAUTHN "Build WebAuthn scheme module" on)
if (WITH_SCHEME_WEBAUTHN)
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

  if ("${DISTRIB_CODENAME}" STREQUAL "ubuntu")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libcbor0.6|libcbor0.8")
  endif ()
  if ("${DISTRIB_CODENAME}" STREQUAL "debian" AND NOT ${RELEASE_CODENAME} STREQUAL "stretch")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libcbor0|libcbor0.8")
  endif ()

  if (NOT Rhonabwy_FOUND)
    find_package(Rhonabwy ${RHONABWY_VERSION_REQUIRED} REQUIRED)
    if ("${RHONABWY_VERSION_STRING}" VERSION_GREATER_EQUAL "${RHONABWY_VERSION_REQUIRED}")
        message(STATUS "Rhonabwy found: ${RHONABWY_VERSION_STRING}")
    else ()
        message( FATAL_ERROR "Rhonabwy version required: ${RHONABWY_VERSION_REQUIRED} - version installed: ${RHONABWY_VERSION_STRING}")
    endif ()
  endif ()

  add_library(schememodwebauthn MODULE ${LIB_SRC})
  set_target_properties(schememodwebauthn PROPERTIES
      COMPILE_OPTIONS "-Wextra;-Wconversion"
      LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/scheme")
  target_link_libraries(schememodwebauthn ${GLWD_LIBS} CBOR::CBOR OpenLDAP::OpenLDAP Rhonabwy::Rhonabwy)
  list(APPEND SCHEME_MODULES schememodwebauthn)
endif ()

option(WITH_SCHEME_CERTIFICATE "Build certificate scheme module" on)
if (WITH_SCHEME_CERTIFICATE)
  set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${SCHEME_MODULES_SRC_PATH}/certificate.c)

  add_library(schememodcertificate MODULE ${LIB_SRC})
  set_target_properties(schememodcertificate PROPERTIES
      COMPILE_OPTIONS "-Wextra;-Wconversion"
      LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/scheme")
  target_link_libraries(schememodcertificate ${GLWD_LIBS})
  list(APPEND SCHEME_MODULES schememodcertificate)
endif ()

option(WITH_SCHEME_HTTP "Build HTTP Basic Auth scheme module" on)
if (WITH_SCHEME_HTTP)
  set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${SCHEME_MODULES_SRC_PATH}/http.c)

  add_library(schememodhttp MODULE ${LIB_SRC})
  set_target_properties(schememodhttp PROPERTIES
      COMPILE_OPTIONS "-Wextra;-Wconversion"
      LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/scheme")
  target_link_libraries(schememodhttp ${GLWD_LIBS})
  list(APPEND SCHEME_MODULES schememodhttp)
endif ()

option(WITH_SCHEME_OAUTH2 "Build Oauth2/OIDC scheme module" on)
if (WITH_SCHEME_OAUTH2)
  set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${SCHEME_MODULES_SRC_PATH}/oauth2.c)

  if (NOT ${RELEASE_CODENAME} STREQUAL "stretch" AND NOT ${RELEASE_CODENAME} STREQUAL "bionic")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}")
  endif ()

  set(SCHEME_OAUTH2_LIBS )

  if (NOT Rhonabwy_FOUND)
    find_package(Rhonabwy ${RHONABWY_VERSION_REQUIRED} REQUIRED)
    if ("${RHONABWY_VERSION_STRING}" VERSION_GREATER_EQUAL "${RHONABWY_VERSION_REQUIRED}")
        message(STATUS "Rhonabwy found: ${RHONABWY_VERSION_STRING}")
    else ()
        message( FATAL_ERROR "Rhonabwy version required: ${RHONABWY_VERSION_REQUIRED} - version installed: ${RHONABWY_VERSION_STRING}")
    endif ()
  endif ()
  list(APPEND SCHEME_OAUTH2_LIBS Rhonabwy::Rhonabwy)

  find_package(Iddawc ${IDDAWC_VERSION_REQUIRED} REQUIRED)
  if ("${IDDAWC_VERSION_STRING}" VERSION_GREATER_EQUAL "${IDDAWC_VERSION_REQUIRED}")
      message(STATUS "Iddawc found: ${IDDAWC_VERSION_STRING}")
  else ()
      message( FATAL_ERROR "Iddawc version required: ${IDDAWC_VERSION_REQUIRED} - version installed: ${IDDAWC_VERSION_STRING}")
  endif ()
  list(APPEND SCHEME_OAUTH2_LIBS Iddawc::Iddawc)

  add_library(schememodoauth2 MODULE ${LIB_SRC})
  set_target_properties(schememodoauth2 PROPERTIES
                        COMPILE_OPTIONS "-Wextra;-Wconversion"
                        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/scheme")
  target_link_libraries(schememodoauth2 ${GLWD_LIBS} ${SCHEME_OAUTH2_LIBS})
  list(APPEND SCHEME_MODULES schememodoauth2)
endif ()

# plugins modules

if (WITH_MOCK OR BUILD_GLEWLWYD_TESTING)
  set(MOCK_LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${PLUGIN_MODULES_SRC_PATH}/mock.c)

  set(MOCK_LIBS "-ldl")

  add_library(pluginmodmock MODULE ${MOCK_LIB_SRC})
  set_target_properties(pluginmodmock PROPERTIES
      COMPILE_OPTIONS "-Wextra;-Wconversion"
      LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugin")
  target_link_libraries(pluginmodmock ${MOCK_LIBS})
  list(APPEND PLUGIN_MODULES pluginmodmock)
endif ()

option(WITH_PLUGIN_OAUTH2 "Build legacy oauth2 plugin module" on)
if (WITH_PLUGIN_OAUTH2)

  if (NOT Rhonabwy_FOUND)
    find_package(Rhonabwy ${RHONABWY_VERSION_REQUIRED} REQUIRED)
    if ("${RHONABWY_VERSION_STRING}" VERSION_GREATER_EQUAL "${RHONABWY_VERSION_REQUIRED}")
        message(STATUS "Rhonabwy found: ${RHONABWY_VERSION_STRING}")
    else ()
        message( FATAL_ERROR "Rhonabwy version required: ${RHONABWY_VERSION_REQUIRED} - version installed: ${RHONABWY_VERSION_STRING}")
    endif ()
  endif ()

  include_directories(${RESOURCES_SRC_PATH})
  set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${PLUGIN_MODULES_SRC_PATH}/protocol_oauth2.c ${RESOURCES_SRC_PATH}/glewlwyd_resource.c ${RESOURCES_SRC_PATH}/glewlwyd_resource.h)

  add_library(protocol_oauth2 MODULE ${LIB_SRC})
  set_target_properties(protocol_oauth2 PROPERTIES
      COMPILE_OPTIONS "-Wextra;-Wconversion"
      LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugin")
  target_link_libraries(protocol_oauth2 ${GLWD_LIBS} Rhonabwy::Rhonabwy)
  list(APPEND PLUGIN_MODULES protocol_oauth2)
endif ()

option(WITH_PLUGIN_OIDC "Build OpenID Connect plugin module" on)
if (WITH_PLUGIN_OIDC)

  if (NOT Rhonabwy_FOUND)
    find_package(Rhonabwy ${RHONABWY_VERSION_REQUIRED} REQUIRED)
    if ("${RHONABWY_VERSION_STRING}" VERSION_GREATER_EQUAL "${RHONABWY_VERSION_REQUIRED}")
        message(STATUS "Rhonabwy found: ${RHONABWY_VERSION_STRING}")
    else ()
        message( FATAL_ERROR "Rhonabwy version required: ${RHONABWY_VERSION_REQUIRED} - version installed: ${RHONABWY_VERSION_STRING}")
    endif ()
  endif ()

  include_directories(${RESOURCES_SRC_PATH})
  set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${PLUGIN_MODULES_SRC_PATH}/protocol_oidc.c)

  add_library(protocol_oidc MODULE ${LIB_SRC})
  set_target_properties(protocol_oidc PROPERTIES
      COMPILE_OPTIONS "-Wextra;-Wconversion"
      LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugin")
  target_link_libraries(protocol_oidc ${GLWD_LIBS} Rhonabwy::Rhonabwy)
  list(APPEND PLUGIN_MODULES protocol_oidc)
endif ()

option(WITH_PLUGIN_REGISTER "Build register plugin module" on)
if (WITH_PLUGIN_REGISTER)

  set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/glewlwyd-common.h ${CMAKE_CURRENT_SOURCE_DIR}/src/misc.c ${PLUGIN_MODULES_SRC_PATH}/register.c)

  add_library(protocol_register MODULE ${LIB_SRC})
  set_target_properties(protocol_register PROPERTIES
      COMPILE_OPTIONS "-Wextra;-Wconversion"
      LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugin")
  target_link_libraries(protocol_register ${GLWD_LIBS})
  list(APPEND PLUGIN_MODULES protocol_register)
endif ()

# tests

option(BUILD_GLEWLWYD_TESTING "Build the testing tree" OFF)

if (BUILD_GLEWLWYD_TESTING)
    set(WITH_MOCK ON)
    find_package(Check REQUIRED)
    if (CHECK_FOUND)
        if (NOT WIN32 AND NOT APPLE)
            include(FindSubunit)
            find_package(Subunit REQUIRED)
        endif ()

        enable_testing()

        set(CMAKE_CTEST_COMMAND ctest -V)

        set(TST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)
        set(U_RESOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/docs/resources/ulfius/)
        set(TST_LIBS Check::Check)
        if (NOT WIN32)
            find_package(Threads REQUIRED)
            list(APPEND TST_LIBS ${CMAKE_THREAD_LIBS_INIT} m)
        endif ()
        if (NOT APPLE AND NOT WIN32)
            list(APPEND TST_LIBS rt)
        endif ()
        if (NOT WIN32 AND NOT APPLE)
            list(APPEND TST_LIBS Subunit::Subunit)
        endif ()

        list(APPEND TST_LIBS ${GLWD_LIBS})

        set(TESTS )
        list(APPEND TESTS glewlwyd_admin_mod_type
                  glewlwyd_admin_mod_user
                  glewlwyd_admin_mod_user_middleware
                  glewlwyd_admin_mod_user_auth_scheme
                  glewlwyd_admin_mod_client
                  glewlwyd_admin_mod_plugin
                  glewlwyd_admin_api_key
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
                  glewlwyd_crud_user_middleware
                  glewlwyd_crud_client
                  glewlwyd_crud_scope
                  glewlwyd_crud_misc_config
                  glewlwyd_mod_user_http
                  glewlwyd_mod_user_irl
                  glewlwyd_mod_user_multiple_password_irl
                  glewlwyd_mod_client_irl
                  glewlwyd_profile_delete
                  glewlwyd_scheme_forbidden
                  glewlwyd_mail_on_connection
                  glewlwyd_geolocation
                  glewlwyd_mail_on_scheme_register
                  glewlwyd_mail_on_update_password
                  )

        if (WITH_PLUGIN_OAUTH2)
          list(APPEND TST_LIBS ${GNUTLS_LIBRARIES} Rhonabwy::Rhonabwy)
          list(APPEND TESTS
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
                  glewlwyd_oauth2_refresh_manage_session
                  glewlwyd_oauth2_irl
                  glewlwyd_oauth2_code_challenge
                  glewlwyd_oauth2_token_introspection
                  glewlwyd_oauth2_token_revocation
                  glewlwyd_oauth2_device_authorization
                  glewlwyd_oauth2_code_replay
                  glewlwyd_oauth2_scheme_required
                  )
        endif ()

        if (WITH_PLUGIN_OIDC)
          list(APPEND TST_LIBS ${GNUTLS_LIBRARIES} Rhonabwy::Rhonabwy)
          list(APPEND TESTS
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
                  glewlwyd_oidc_profile_impersonate
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
                  glewlwyd_oidc_jwt_encrypted
                  glewlwyd_oidc_jwks_config
                  glewlwyd_oidc_session_management
                  glewlwyd_oidc_device_authorization
                  glewlwyd_oidc_refresh_token_one_use
                  glewlwyd_oidc_client_registration_management
                  glewlwyd_oidc_code_replay
                  glewlwyd_oidc_scheme_required
                  glewlwyd_oidc_dpop
                  glewlwyd_oidc_resource
                  glewlwyd_oidc_rich_auth_requests
                  glewlwyd_oidc_pushed_auth_requests
                  glewlwyd_oidc_reduced_scope
                  glewlwyd_oidc_all_algs
                  glewlwyd_oidc_ciba
                  glewlwyd_oidc_auth_iss_is
                  glewlwyd_oidc_jarm
                  glewlwyd_oidc_fapi
                  iddawc_resource_tester
                  )
          set(TESTS_SSL ${TESTS_SSL} glewlwyd_oidc_client_certificate)
        endif ()

        set(TESTS_PROMETHEUS glewlwyd_prometheus)

        set(TESTS_SINGLE_USER_SESSION glewlwyd_auth_single_user_session)

        if (WITH_PLUGIN_REGISTER)
          list(APPEND TESTS glewlwyd_register)
        endif ()

        if (WITH_SCHEME_OTP)
          list(APPEND TST_LIBS OATH::OATH)
          list(APPEND TESTS glewlwyd_scheme_otp)
        endif ()

        if (WITH_SCHEME_WEBAUTHN)
          list(APPEND TST_LIBS CBOR::CBOR)
          list(APPEND TESTS glewlwyd_scheme_webauthn)
        endif ()

        if (WITH_SCHEME_EMAIL)
          list(APPEND TESTS glewlwyd_scheme_mail)
        endif ()

        if (WITH_SCHEME_RETYPE_PASSWORD)
          list(APPEND TESTS glewlwyd_scheme_retype_password)
        endif ()

        if (WITH_SCHEME_HTTP)
          list(APPEND TESTS glewlwyd_scheme_http)
        endif ()

        if (WITH_SCHEME_OAUTH2)
          list(APPEND TST_LIBS Iddawc::Iddawc)
          list(APPEND TESTS glewlwyd_scheme_oauth2)
        endif ()

        if (WITH_SCHEME_CERTIFICATE)
          set(TESTS_SSL ${TESTS_SSL} glewlwyd_scheme_certificate)
        endif ()

        configure_file(
            "${G_CMAKE_MODULE_PATH}/CTestCustom.cmake.in"
            "${CMAKE_CURRENT_BINARY_DIR}/CTestCustom.cmake"
            @ONLY)

        set(COUNTER 0)

        foreach (t ${TESTS})
          if (NOT ${t} MATCHES "iddawc_resource_tester$")
            add_executable(${t} EXCLUDE_FROM_ALL ${TST_DIR}/${t}.c ${TST_DIR}/unit-tests.c ${TST_DIR}/unit-tests.h)
          else ()
            add_executable(${t} EXCLUDE_FROM_ALL ${TST_DIR}/${t}.c ${TST_DIR}/unit-tests.c ${TST_DIR}/unit-tests.h ${U_RESOURCE_DIR}/iddawc_resource.c ${U_RESOURCE_DIR}/iddawc_resource.h)
          endif ()
          target_include_directories(${t} PUBLIC ${TST_DIR})
          target_link_libraries(${t} PUBLIC ${TST_LIBS})
          if (NOT ${t} MATCHES "_irl$")
            add_test(NAME ${t}
                    WORKING_DIRECTORY ${TST_DIR}
                    COMMAND ${t})
          elseif (${t} MATCHES "_user_irl$")
            FILE(GLOB JsonIrl ${TST_DIR}/mod_user_*.json)
            foreach (j ${JsonIrl})
                add_test(NAME "${t}_${COUNTER}"
                        WORKING_DIRECTORY ${TST_DIR}
                        COMMAND ${t} ${j})
                MATH(EXPR COUNTER "${COUNTER}+1")
            endforeach ()
          elseif (${t} MATCHES "_user_multiple_password_irl$")
            FILE(GLOB JsonIrl ${TST_DIR}/mod_multiple_password_*.json)
            foreach (j ${JsonIrl})
                add_test(NAME "${t}_${COUNTER}"
                        WORKING_DIRECTORY ${TST_DIR}
                        COMMAND ${t} ${j})
                MATH(EXPR COUNTER "${COUNTER}+1")
            endforeach ()
          elseif (${t} MATCHES "_client_irl$")
            FILE(GLOB JsonIrl ${TST_DIR}/mod_client_*.json)
            foreach (j ${JsonIrl})
                add_test(NAME "${t}_${COUNTER}"
                        WORKING_DIRECTORY ${TST_DIR}
                        COMMAND ${t} ${j})
                MATH(EXPR COUNTER "${COUNTER}+1")
            endforeach ()
          elseif (${t} MATCHES "_oauth2_irl$")
            FILE(GLOB JsonIrl ${TST_DIR}/plugin_oauth2_*.json)
            foreach (j ${JsonIrl})
                add_test(NAME "${t}_${COUNTER}"
                        WORKING_DIRECTORY ${TST_DIR}
                        COMMAND ${t} ${j})
                MATH(EXPR COUNTER "${COUNTER}+1")
            endforeach ()
          elseif (${t} MATCHES "_oidc_irl$")
            FILE(GLOB JsonIrl ${TST_DIR}/plugin_oidc_*.json)
            foreach (j ${JsonIrl})
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

        foreach (t ${TESTS_PROMETHEUS})
          add_executable(${t} EXCLUDE_FROM_ALL ${TST_DIR}/${t}.c ${TST_DIR}/unit-tests.c ${TST_DIR}/unit-tests.h)
          target_include_directories(${t} PUBLIC ${TST_DIR})
          target_link_libraries(${t} PUBLIC ${TST_LIBS})
        endforeach ()

        foreach (t ${TESTS_SINGLE_USER_SESSION})
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
install(TARGETS ${USER_MIDDLEWARE_MODULES}
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/glewlwyd/user_middleware)
install(TARGETS ${CLIENT_MODULES}
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/glewlwyd/client)
install(TARGETS ${SCHEME_MODULES}
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/glewlwyd/scheme)
install(TARGETS ${PLUGIN_MODULES}
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/glewlwyd/plugin)
install(DIRECTORY docs/database/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/database/ COMPONENT runtime)
install(DIRECTORY docs/fail2ban/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/fail2ban/ COMPONENT runtime)
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
install(FILES docs/EMAIL.md
    DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/GETTING_STARTED.md
    DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/INSTALL.md
    DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/HTTP.md
    DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/OAUTH2.md
    DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/OAUTH2_SCHEME.md
    DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/OIDC.md
    DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/OTP.md
    DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/README.md
    DESTINATION ${CMAKE_INSTALL_DATADIR}/glewlwyd/docs/ COMPONENT runtime)
install(FILES docs/REGISTER.md
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
INSTALL(FILES docs/glewlwyd.8
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man8 COMPONENT runtime)

set(TARGETS glewlwyd)

install(TARGETS ${TARGETS}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  CONFIGURATIONS Release)

# uninstall target

if (NOT TARGET uninstall)
  configure_file(
    "${G_CMAKE_MODULE_PATH}/CMakeUninstall.cmake.in"
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
message(STATUS "Build scheme module WebAuthn:         ${WITH_SCHEME_WEBAUTHN}")
message(STATUS "Build scheme module TLS Certificate:  ${WITH_SCHEME_CERTIFICATE}")
message(STATUS "Build scheme module HTTP:             ${WITH_SCHEME_HTTP}")
message(STATUS "Build scheme module OAuth2:           ${WITH_SCHEME_OAUTH2}")
message(STATUS "Build plugin module legacy oauth2:    ${WITH_PLUGIN_OAUTH2}")
message(STATUS "Build plugin module OpenID Connect:   ${WITH_PLUGIN_OIDC}")
message(STATUS "Build plugin register new account:    ${WITH_PLUGIN_REGISTER}")
message(STATUS "Build the testing tree:               ${BUILD_GLEWLWYD_TESTING}")
message(STATUS "Build RPM package:                    ${BUILD_RPM}")
