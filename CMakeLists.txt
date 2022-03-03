cmake_minimum_required (VERSION 3.20)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/307lib/307modules")

include(VersionTag)

GET_VERSION_TAG("${CMAKE_CURRENT_SOURCE_DIR}" "ARPQUERY")

project("arpQuery" VERSION "${ARPQUERY_VERSION}")

add_subdirectory("307lib")
add_subdirectory("arpQuery")
