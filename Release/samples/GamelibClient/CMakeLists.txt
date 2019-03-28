if (NOT WINDOWS_STORE AND NOT WINDOWS_PHONE)
  find_package(OpenSSL 1.0.0 REQUIRED)

#  message(STATUS "=======================================================")
#  message(STATUS ${OPENSSL_LIBRARIES})
#  message(STATUS ${OPENSSL_INCLUDE_DIR})
#  message(STATUS "=======================================================")
  
  find_path(STEAM_INCLUDE_DIR NAMES steam/steam_api.h PATHS "./include")

  if (APPLE)
    set(GAMELIBCLIENT_SOURCES
        BaseMenu.cpp
        GameClient.cpp
        Main.cpp
        MainMenu.cpp
        gameengineosx.mm
        glstringosx.mm
        stdafx.cpp
        GamelibClient.cpp
    )

    set(GAMELIBCLIENT_RESOURCES
    )
    add_executable( gamelibclient MACOSX_BUNDLE
        ${GAMELIBCLIENT_SOURCES}
        ${GAMELIBCLIENT_PUBLIC_HEADERS}
        ${GAMELIBCLIENT_PROJECT_HEADERS}
        ${GAMELIBCLIENT_PRIVATE_HEADERS}
        ${GAMELIBCLIENT_RESOURCES}
    )
    set( GAMELIBCLIENT_STATIC_DEPENDENCIES
        cpprest ${OPENSSL_LIBRARIES}
    )

    find_library( COCOA_LIBRARY Cocoa)
    message( STATUS "COCOA_LIBRARY is ${COCOA_LIBRARY}")
    find_library( FOUNDATION_LIBRARY Foundation)
    message( STATUS "FOUNDATION_LIBRARY is ${FOUNDATION_LIBRARY}")
    find_library( IOKIT_LIBRARY IOKit)
    message( STATUS "IOKIT_LIBRARY is ${IOKIT_LIBRARY}")
    find_library( OPEN_AL_LIBRARY OpenAL)
    message( STATUS "OPEN_AL_LIBRARY is ${OPEN_AL_LIBRARY}")
    find_library( OPEN_GL_LIBRARY OpenGL)
    message( STATUS "OPEN_GL_LIBRARY is ${OPEN_GL_LIBRARY}")
    find_library( STEAM_API_LIBRARY steam_api PATHS "./lib/steam/osx32")
    message( STATUS "STEAM_API_LIBRARY is ${STEAM_API_LIBRARY}")

    set( GAMELIBCLIENT_DEPENDENCIES
      ${COCOA_LIBRARY}
      ${FOUNDATION_LIBRARY}
      ${IOKIT_LIBRARY}
      ${OPEN_AL_LIBRARY}
      ${OPEN_GL_LIBRARY}
      ${STEAM_API_LIBRARY}
    )

    target_compile_definitions(gamelibclient PUBLIC -DOSX -DPOSIX)
    
    add_dependencies(gamelibclient cpprest)
    add_dependencies(gamelibclient ZERO_CHECK)

    target_link_libraries( gamelibclient
      ${GAMELIBCLIENT_STATIC_DEPENDENCIES}
      ${GAMELIBCLIENT_DEPENDENCIES}
    )
    target_include_directories( gamelibclient
      PRIVATE
      ${OPENSSL_INCLUDE_DIR}
      ${STEAM_INCLUDE_DIR}
    )
    
    set_source_files_properties(
        ${GAMELIBCLIENT_RESOURCES}
        PROPERTIES
        MACOSX_PACKAGE_LOCATION
        Resources
    )
    set_target_properties(
        gamelibclient
        PROPERTIES
        MACOSX_BUNDLE_INFO_PLIST
        ${CMAKE_CURRENT_LIST_DIR}/Info.plist
    )

    add_custom_command(
        TARGET gamelibclient POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_CURRENT_SOURCE_DIR}/steam_appid.txt
        ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${CMAKE_BUILD_TYPE}/steam_appid.txt
    )
    add_custom_command(
        TARGET gamelibclient POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/steam/osx32/libsteam_api.dylib
        ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${CMAKE_BUILD_TYPE}/libsteam_api.dylib
    )
  else()
    find_library(STEAM_LIBRARIES NAMES steam_api64.lib PATHS "./lib/steam/win64")
    message(STATUS ${STEAM_LIBRARIES})
    message(STATUS ${STEAM_INCLUDE_DIR})
    
    find_path(SHIFT_INCLUDE_DIR NAMES ShiftgamesAPI.h PATHS "./include/shift") 
    find_library(SHIFT_LIBRARIES NAMES ShiftgamesAppSDKCpp.lib PATHS "./lib/shift/v141/x64/${CMAKE_BUILD_TYPE}")
    message(STATUS ${SHIFT_LIBRARIES})
    message(STATUS ${SHIFT_INCLUDE_DIR})

    set(programfilesx86 "ProgramFiles(x86)")
    set(DIRECTX_DIR "$ENV{${programfilesx86}}/Microsoft DirectX SDK (June 2010)")
    find_path(DX_INCLUDE_DIR NAMES d3d9.h d3dx9.h PATHS ${DIRECTX_DIR}/Include)
    find_library(D3D9_LIBRARIES NAMES d3d9.lib PATHS ${DIRECTX_DIR}/Lib/x64)
    find_library(D3DX9_LIBRARIES NAMES d3dx9.lib PATHS ${DIRECTX_DIR}/Lib/x64)
    message(STATUS ${DX_INCLUDE_DIR})
    message(STATUS ${D3D9_LIBRARIES})
    message(STATUS ${D3DX9_LIBRARIES})

    set(GAMELIBCLIENT_SOURCES
        BaseMenu.cpp
        GameClient.cpp
        Main.cpp
        MainMenu.cpp
        gameenginewin32.cpp
        stdafx.cpp
        GamelibClient.cpp
    )

    add_executable(gamelibclient WIN32
      ${GAMELIBCLIENT_SOURCES}
    )

    target_link_libraries(gamelibclient cpprest ${OPENSSL_LIBRARIES} ${STEAM_LIBRARIES} ${SHIFT_LIBRARIES} ${D3D9_LIBRARIES} ${D3DX9_LIBRARIES})
    target_include_directories(gamelibclient PRIVATE ${OPENSSL_INCLUDE_DIR} ${STEAM_INCLUDE_DIR} ${SHIFT_INCLUDE_DIR} ${DX_INCLUDE_DIR})

    add_custom_command(
        TARGET gamelibclient POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_CURRENT_SOURCE_DIR}/steam_appid.txt
        ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${CMAKE_BUILD_TYPE}/steam_appid.txt
    )
    add_custom_command(
        TARGET gamelibclient POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/steam/win64/steam_api64.dll
        ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${CMAKE_BUILD_TYPE}/steam_api64.dll
    )
    add_custom_command(
        TARGET gamelibclient POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
	${CMAKE_CURRENT_SOURCE_DIR}/lib/shift/v141/x64/${CMAKE_BUILD_TYPE}/ShiftgamesAppSDKCpp.dll
        ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${CMAKE_BUILD_TYPE}/ShiftgamesAppSDKCpp.dll
    )
    add_custom_command(
        TARGET gamelibclient POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
	${CMAKE_CURRENT_SOURCE_DIR}/lib/shift/v141/x64/${CMAKE_BUILD_TYPE}/ShiftgamesAppSDKCore.dll
	${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${CMAKE_BUILD_TYPE}/ShiftgamesAppSDKCore.dll
    )

  endif()

endif()
