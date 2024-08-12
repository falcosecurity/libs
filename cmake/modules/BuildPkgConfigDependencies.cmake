# Get all dependencies for ${lib} and add them to ${LIBDIRS_VAR} and ${LIBS_VAR}. Ignore any
# dependencies in the list ${ignored} to: - avoid infinite recursion - avoid libscap dependencies in
# libsinsp.pc (which requires libscap.pc and pulls them in that way)
function(add_pkgconfig_library LIBDIRS_VAR LIBS_VAR lib ignored)

	# if it's not a target, it doesn't have dependencies we know or care about
	if(NOT TARGET ${lib})
		return()
	endif()

	# get the libraries that ${lib} links to
	get_target_property(PKGCONFIG_LIBRARIES ${lib} LINK_LIBRARIES)
	if("${PKGCONFIG_LIBRARIES}" STREQUAL "PKGCONFIG_LIBRARIES-NOTFOUND")
		return()
	endif()

	get_property(
		target_type
		TARGET ${lib}
		PROPERTY TYPE
	)
	foreach(dep ${PKGCONFIG_LIBRARIES})
		# ignore dependencies in the list ${ignored}
		if(${dep} IN_LIST "${ignored}")
			continue()
		endif()

		if(${target_type} STREQUAL "SHARED_LIBRARY")
			# for shared libraries, do not add static libraries as dependencies
			if(TARGET ${dep})
				# skip static libraries which are CMake targets
				get_property(
					dep_target_type
					TARGET ${dep}
					PROPERTY TYPE
				)
				if(${dep_target_type} STREQUAL "STATIC_LIBRARY")
					continue()
				endif()
			else()
				# skip static libraries which are just file paths
				get_filename_component(ext ${dep} LAST_EXT)
				if("${ext}" STREQUAL "${CMAKE_STATIC_LIBRARY_SUFFIX}")
					continue()
				endif()
			endif()
		elseif(${target_type} STREQUAL "STATIC_LIBRARY")
			# for static libraries which are not CMake targets, redirect them to
			# ${libdir}/${LIBS_PACKAGE_NAME} note that ${libdir} is not a CMake variable, but a
			# pkgconfig variable, so we quote it and end up with a literal ${libdir} in the
			# pkgconfig file
			if(NOT TARGET ${dep})
				get_filename_component(filename ${dep} NAME)
				set(dep "\${libdir}/${LIBS_PACKAGE_NAME}/${filename}")
			endif()
		endif()

		add_pkgconfig_dependency(${LIBDIRS_VAR} ${LIBS_VAR} ${dep} "${ignored}")
	endforeach()

	# Remove duplicate search paths. We cannot remove duplicates from ${LIBS_VAR} because the order
	# of libraries is important.
	list(REMOVE_DUPLICATES ${LIBDIRS_VAR})

	set(${LIBS_VAR}
		${${LIBS_VAR}}
		PARENT_SCOPE
	)
	set(${LIBDIRS_VAR}
		${${LIBDIRS_VAR}}
		PARENT_SCOPE
	)
endfunction()

function(add_pkgconfig_dependency LIBDIRS_VAR LIBS_VAR lib ignored)
	if(${lib} IN_LIST ignored)
		# already processed, avoid infinite recursion
	elseif(${lib} MATCHES "^-")
		# We have a flag. Pass it through unchanged.
		list(APPEND ${LIBS_VAR} ${lib})
	elseif(${lib} MATCHES "/")
		# We have a path. Convert it to -L<dir> + -l<lib>.
		get_filename_component(lib_dir ${lib} DIRECTORY)
		list(APPEND ${LIBDIRS_VAR} -L${lib_dir})
		get_filename_component(lib_base ${lib} NAME_WE)
		string(REGEX REPLACE "^lib" "" lib_base ${lib_base})
		list(APPEND ${LIBS_VAR} -l${lib_base})
	else()
		# Assume we have a plain library name. Prefix it with "-l". Then recurse into its
		# dependencies but ignore the library itself, so we don't end up in an infinite loop with
		# cyclic dependencies
		list(APPEND ${LIBS_VAR} -l${lib})
		list(APPEND ignored ${lib})
		add_pkgconfig_library(${LIBDIRS_VAR} ${LIBS_VAR} ${lib} "${ignored}")
	endif()
	set(${LIBS_VAR}
		${${LIBS_VAR}}
		PARENT_SCOPE
	)
	set(${LIBDIRS_VAR}
		${${LIBDIRS_VAR}}
		PARENT_SCOPE
	)
endfunction()
