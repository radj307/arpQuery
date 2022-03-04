cmake_minimum_required (VERSION 3.20)

include(VersionTag)
MAKE_VERSION_HEADER("${CMAKE_CURRENT_SOURCE_DIR}/version.h" "ARPQUERY" "${ARPQUERY_VERSION}")

if (WIN32)
	include(ResourceMaker)
	set(ARPQUERY_RESOURCE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/arpQuery.rc")
	file(REMOVE "${ARPQUERY_RESOURCE_FILE}")
	file(TOUCH "${ARPQUERY_RESOURCE_FILE}")

	CREATE_VERSION_RESOURCE(
		"${ARPQUERY_RESOURCE_FILE}"
		"${ARPQUERY_VERSION_MAJOR}"
		"${ARPQUERY_VERSION_MINOR}"
		"${ARPQUERY_VERSION_PATCH}"
		"radj307"
		"Commandline ARP table querying utility."
		"arpQuery"
		"GPLv2"
		"arpQuery"
		"arpQuery"
	)
	APPEND_ICON_RESOURCE("${ARPQUERY_RESOURCE_FILE}" "${CMAKE_CURRENT_SOURCE_DIR}/arpQuery1.ico")
endif()

file(GLOB SRCS
	RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}"
	CONFIGURE_DEPENDS
	"*.c*"
)
file(GLOB HEADERS
	RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}"
	CONFIGURE_DEPENDS
	"*.h*"
)
add_executable(arpQuery "${SRCS}" "${ARPQUERY_RESOURCE_FILE}")

set_property(TARGET arpQuery PROPERTY CXX_STANDARD 20)
set_property(TARGET arpQuery PROPERTY CXX_STANDARD_REQUIRED ON)
if (MSVC)
	target_compile_options(arpQuery PUBLIC "/Zc:__cplusplus")
endif()

target_sources(arpQuery PUBLIC "${HEADERS}")

target_link_libraries(arpQuery PUBLIC shared tokenlib TermAPI strlib filelib)

include(PackageInstaller)
INSTALL_EXECUTABLE(arpQuery "${CMAKE_INSTALL_PREFIX}/bin")

