cmake_minimum_required(VERSION 4.0.1)
project(sc2rtwp CXX)

# Organize projects into folders inside solution
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

function(add_target TARGET_NAME TARGET_TYPE)
	cmake_parse_arguments(PARSE_ARGV 2 ARG "STATIC_RUNTIME" "CATEGORY" "DEPS_PUBLIC;DEPS_PRIVATE;DEPS_INTERFACE")

	# define new target
	if(TARGET_TYPE STREQUAL "DLL")
		add_library(${TARGET_NAME} SHARED)
	elseif(TARGET_TYPE STREQUAL "LIB")
		add_library(${TARGET_NAME} STATIC)
	elseif(TARGET_TYPE STREQUAL "EXE_GUI")
		add_executable(${TARGET_NAME} WIN32)
	elseif(TARGET_TYPE STREQUAL "EXE_CONSOLE")
		add_executable(${TARGET_NAME})
	else()
		message(FATAL_ERROR "Target ${TARGET_NAME} specified unsupported target type ${TARGET_TYPE}.")
	endif()

	# latest standard support
	set_property(TARGET ${TARGET_NAME} PROPERTY CXX_STANDARD 26)

	# make sure different dlls/exes use different compile PDBs, so that they can be compiled concurrently
	if(NOT TARGET_TYPE STREQUAL "LIB")
		set_target_properties(${TARGET_NAME} PROPERTIES COMPILE_PDB_NAME "vc-${TARGET_NAME}")
	endif()

	# add current directory to include path for this target and its dependencies
	target_include_directories(${TARGET_NAME} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src/${TARGET_NAME}")

	# set category, if desired
	if(ARG_CATEGORY)
		set_property(TARGET ${TARGET_NAME} PROPERTY FOLDER ${ARG_CATEGORY})
	endif()

	# gather sources
	file(GLOB_RECURSE TARGET_SOURCES RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" CONFIGURE_DEPENDS "src/${TARGET_NAME}/${TARGET_NAME}/*.cxx" "src/${TARGET_NAME}/${TARGET_NAME}/*.h")
	file(GLOB_RECURSE TARGET_MODULE_INTERFACES RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" CONFIGURE_DEPENDS "src/${TARGET_NAME}/${TARGET_NAME}/*.ixx")

	# add filtered sources to target and assign IDE source groups
	target_sources(${TARGET_NAME}
		PRIVATE ${TARGET_SOURCES}
		PRIVATE FILE_SET CXX_MODULES FILES ${TARGET_MODULE_INTERFACES}
	)
	source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}/src/${TARGET_NAME}/${TARGET_NAME}" PREFIX "Sources" FILES ${TARGET_SOURCES} ${TARGET_MODULE_INTERFACES})

	# add dependencies
	target_link_libraries(${TARGET_NAME}
		PUBLIC    ${ARG_DEPS_PUBLIC}
		PRIVATE   ${ARG_DEPS_PRIVATE}
		INTERFACE ${ARG_DEPS_INTERFACE}
	)

	# link CRT statically if desired
	if(ARG_STATIC_RUNTIME)
		set_property(TARGET ${TARGET_NAME} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
	endif()
endfunction()

add_target(common LIB DEPS_PRIVATE ntdll)
add_target(sc2rtwp EXE_CONSOLE DEPS_PRIVATE common)
add_target(sc2rtwp_in DLL
	#STATIC_RUNTIME
	DEPS_PRIVATE common)
add_target(logger EXE_CONSOLE DEPS_PRIVATE common)
add_target(test_target EXE_CONSOLE)
