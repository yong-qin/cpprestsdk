if (NOT WINDOWS_STORE AND NOT WINDOWS_PHONE)
   find_package(OpenSSL 1.0.0 REQUIRED)

  find_path(STEAM_INCLUDE_DIR NAMES steam/steam_api.h PATHS "./include")
#  if (WIN32)
#    find_library(STEAM_LIBRARIES NAMES steam_api64.lib PATHS "./lib/steam/win64")
#  endif()
#  message(STATUS "=======================================================")
#  message(STATUS ${OPENSSL_LIBRARIES})
#  message(STATUS ${OPENSSL_INCLUDE_DIR})
#  message(STATUS ${STEAM_LIBRARIES})
#  message(STATUS ${STEAM_INCLUDE_DIR})
#  message(STATUS "=======================================================")
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
    add_executable(gamelibclient
      GamelibClient.cpp
    )

    target_link_libraries(gamelibclient cpprest ${OPENSSL_LIBRARIES} ${STEAM_LIBRARIES})
    target_include_directories(gamelibclient PRIVATE ${OPENSSL_INCLUDE_DIR} ${STEAM_INCLUDE_DIR})
  endif()

endif()
