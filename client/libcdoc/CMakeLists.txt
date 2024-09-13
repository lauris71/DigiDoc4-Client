cmake_minimum_required(VERSION 3.2)
project(cdoc VERSION 0.0.1)
find_package(Doxygen)
find_package(zlib REQUIRED)
find_package(LibXml2 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(SWIG)
include(GenerateExportHeader)
include(GNUInstallDirs)

find_package(FlatBuffers CONFIG REQUIRED NAMES FlatBuffers Flatbuffers)
set(SIGNCERT "" CACHE STRING "Common name of certificate to used sign binaries, empty skip signing" )
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(INSTALL_FRAMEWORKDIR /Library/Frameworks CACHE STRING "Framework install target")
#set(PUBLIC_HEADER Token.h CDOCReader.h CDOCWriter.h ${CMAKE_BINARY_DIR}/CDOCExport.h)
set(PUBLIC_HEADER Token.h CDOC1Reader.h CDOC1Writer.h CDOCExport.h)
include_directories(${LIBXML2_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR} ${CMAKE_BINARY_DIR} ${CMAKE_SOURCE_DIR})
if(WIN32)
	add_definitions(-DUNICODE -DWIN32_LEAN_AND_MEAN)
	list(APPEND LIBS Crypt32 NCrypt cryptui)
endif()

if(DOXYGEN_FOUND)
#	configure_file(${CMAKE_SOURCE_DIR}/Doxyfile.in Doxyfile @ONLY)
	configure_file(Doxyfile.in Doxyfile @ONLY)
	add_custom_target(docs ALL
		${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		COMMENT "Generating API documentation with Doxygen" VERBATIM
	)
endif()

set(SCHEMAS
        schema/recipients.fbs
        schema/header.fbs
)

add_library(cdoc_private STATIC
	Crypto.cpp
	DDOCReader.cpp
	DDOCWriter.cpp
	XMLReader.cpp
	XMLWriter.cpp
        zstream.cpp zstream.h
        tar.cpp tar.h
        utils.h
        utils.cpp
)
set_property(TARGET cdoc_private PROPERTY POSITION_INDEPENDENT_CODE ON)

target_include_directories(cdoc_private PRIVATE ..)

#add_library(cdoc SHARED
#	CDOCReader.cpp
#	CDOCWriter.cpp
#	Token.cpp
#	${PUBLIC_HEADER}
#	${RESOURCE_FILES}
#)

add_library(cdoc STATIC
    CDOC1Writer.cpp CDOC1Writer.h
    Token.cpp
    cdoc.cpp cdoc.h
    certificate.cpp certificate.h
    ${PUBLIC_HEADER}
    ${RESOURCE_FILES}
    CDOC1Reader.cpp CDOC1Reader.h
    cdoc2.cpp cdoc2.h
    io.cpp io.h
    keys.cpp keys.h
)

set_target_properties(cdoc PROPERTIES
	VERSION ${PROJECT_VERSION}
	SOVERSION 0
	FRAMEWORK_VERSION 0
	FRAMEWORK YES
	PUBLIC_HEADER "${PUBLIC_HEADER}"
	RESOURCE "${RESOURCE_FILES}"
	MACOSX_FRAMEWORK_IDENTIFIER "ee.ria.cdoc"
	MACOSX_FRAMEWORK_SHORT_VERSION_STRING ${PROJECT_VERSION}
	MACOSX_FRAMEWORK_BUNDLE_VERSION ${PROJECT_VERSION}
	C_VISIBILITY_PRESET hidden
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)
generate_export_header(cdoc EXPORT_FILE_NAME CDOCExport.h)
target_link_libraries(cdoc cdoc_private
    $<TARGET_NAME_IF_EXISTS:flatbuffers::flatbuffers>
    $<TARGET_NAME_IF_EXISTS:flatbuffers::flatbuffers_shared>
    ${ZLIB_LIBRARY}
    ${LIBXML2_LIBRARIES}
    ${OPENSSL_CRYPTO_LIBRARY}
    ${LIBS}
)
install(TARGETS cdoc
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	RESOURCE DESTINATION ${CMAKE_INSTALL_DOCDIR}
	PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cdoc
	FRAMEWORK DESTINATION ${INSTALL_FRAMEWORKDIR}
)
target_include_directories(cdoc PRIVATE ..)

foreach(SCHEMA ${SCHEMAS})
        get_filename_component(stem ${SCHEMA} NAME_WE)
        get_filename_component(name ${SCHEMA} NAME)
        set(GENERATED_INCLUDE ${CMAKE_CURRENT_BINARY_DIR}/${stem}_generated.h)
        add_custom_command(
                OUTPUT ${GENERATED_INCLUDE}
                COMMENT "Compiling flatbuffer for ${name}"
                COMMAND flatbuffers::flatc
                        --cpp
                        --scoped-enums
                        -o ${CMAKE_CURRENT_BINARY_DIR}
                        -I ${CMAKE_CURRENT_SOURCE_DIR}
                        ${SCHEMA}
                DEPENDS flatbuffers::flatc ${SCHEMA}
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )
        target_sources(${PROJECT_NAME} PRIVATE ${SCHEMA} ${GENERATED_INCLUDE})
endforeach()

add_executable(cdoc-tool main.cpp)
target_link_libraries(cdoc-tool cdoc)
target_include_directories(cdoc-tool PRIVATE ${CMAKE_BINARY_DIR}/client ..)
if(NOT APPLE)
	install(TARGETS cdoc-tool RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
	install(DIRECTORY ${CMAKE_BINARY_DIR}/doc/ DESTINATION ${CMAKE_INSTALL_DOCDIR})
endif()

if(SWIG_FOUND AND WIN32)
	include(${SWIG_USE_FILE})
	set(CMAKE_SWIG_FLAGS -dllimport cdoc_csharp -namespace cdoc)
	set(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_BINARY_DIR}/csharp)
	set_property(SOURCE cdoc.i PROPERTY CPLUSPLUS ON)
	swig_add_library(cdoc_csharp TYPE SHARED LANGUAGE csharp SOURCES cdoc.i)
	swig_link_libraries(cdoc_csharp cdoc)
	set_target_properties(cdoc_csharp PROPERTIES DEBUG_OUTPUT_NAME "cdoc_csharpd")
	install(TARGETS cdoc_csharp DESTINATION ${CMAKE_INSTALL_BINDIR})
	install(FILES $<TARGET_PDB_FILE:cdoc_csharp> DESTINATION ${CMAKE_INSTALL_BINDIR} OPTIONAL)
	install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/csharp/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cdoc_csharp FILES_MATCHING PATTERN "*.cs")
endif()

if(APPLE)
	add_custom_command(TARGET cdoc-tool POST_BUILD
		COMMAND cp -a $<TARGET_FILE:cdoc-tool> $<TARGET_FILE_DIR:cdoc>/Resources
	)
	if(DOXYGEN_FOUND)
		add_custom_command(TARGET docs POST_BUILD
			COMMAND cp -a ${CMAKE_BINARY_DIR}/doc/* $<TARGET_FILE_DIR:cdoc>/Resources/
		)
	endif()
	set_target_properties(cdoc-tool PROPERTIES
		BUILD_WITH_INSTALL_RPATH YES
		INSTALL_RPATH "@executable_path/../../../..;@executable_path"
	)
#	add_custom_target(codesign DEPENDS cdoc
#		COMMAND codesign -f -s "Developer ID Application: ${SIGNCERT}"
#			$<TARGET_FILE_DIR:cdoc>/Resources/cdoc-tool
#			$<TARGET_FILE_DIR:cdoc>/../..
#	)

    if(SIGNCERT)
		set(PKGEXTRA --sign "Developer ID Installer: ${SIGNCERT}")
	endif()
	add_custom_target(pkg DEPENDS cdoc-tool
		COMMAND make install DESTDIR=install
		COMMAND pkgbuild --root install ${PKGEXTRA}
			${CMAKE_BINARY_DIR}/cdoc_${PROJECT_VERSION}$ENV{VER_SUFFIX}.pkg
	)
	add_custom_target(debugpkg DEPENDS cdoc-tool
		COMMAND dsymutil -o cdoc.dSYM $<TARGET_FILE:cdoc>
		COMMAND dsymutil -o cdoc.dSYM $<TARGET_FILE:cdoc-tool>
		COMMAND zip -r ${CMAKE_BINARY_DIR}/cdoc-dbg_${PROJECT_VERSION}$ENV{VER_SUFFIX}.zip cdoc.dSYM
	)
elseif(WIN32)
	set_target_properties(cdoc PROPERTIES DEBUG_OUTPUT_NAME "cdocd")
	install(FILES $<TARGET_PDB_FILE:cdoc> $<TARGET_PDB_FILE:cdoc-tool> DESTINATION ${CMAKE_INSTALL_BINDIR} OPTIONAL)
else()
	add_custom_target(debs
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
		COMMAND dh_make --createorig --addmissing --defaultless -y -p ${PROJECT_NAME}_${PROJECT_VERSION}
		COMMAND dch --distribution unstable -v ${PROJECT_VERSION} 'Release: ${PROJECT_VERSION}.'
		COMMAND dpkg-buildpackage -rfakeroot -us -uc
	)
endif()
