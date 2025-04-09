cmake_minimum_required(VERSION 3.5) # Or higher if needed by features
project(chatbot_admin_backend CXX)

include(CheckIncludeFileCXX)

# --- C++ Standard Detection Logic ---
check_include_file_cxx(any HAS_ANY)
check_include_file_cxx(string_view HAS_STRING_VIEW)
check_include_file_cxx(coroutine HAS_COROUTINE)
if (NOT "${CMAKE_CXX_STANDARD}" STREQUAL "")
    # Do nothing if already set by user/toolchain
elseif (HAS_ANY AND HAS_STRING_VIEW AND HAS_COROUTINE)
    set(CMAKE_CXX_STANDARD 20)
elseif (HAS_ANY AND HAS_STRING_VIEW)
    set(CMAKE_CXX_STANDARD 17)
else ()
    set(CMAKE_CXX_STANDARD 14)
endif ()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# --- Find Packages (using vcpkg toolchain file) ---
find_package(Drogon REQUIRED CONFIG)    # Find Drogon Framework
find_package(PostgreSQL REQUIRED)       # Find libpq (PostgreSQL client C library)
find_package(OpenSSL REQUIRED)          # Find OpenSSL (for crypto)
find_package(JsonCpp REQUIRED CONFIG)   # Find JsonCpp (Drogon's JSON library)
# Removed: find_package(argon2 REQUIRED CONFIG) # This failed due to missing vcpkg files

# Find header-only jwt-cpp using find_path
find_path(JWT_CPP_INCLUDE_DIRS NAMES "jwt-cpp/jwt.h" # Header file to look for
                         PATHS ${CMAKE_PREFIX_PATH}/include # Search vcpkg include path
                         REQUIRED) # Fail if not found
if (JWT_CPP_INCLUDE_DIRS)
    message(STATUS "Found jwt-cpp headers at: ${JWT_CPP_INCLUDE_DIRS}")
else()
    message(FATAL_ERROR "Could not find jwt-cpp headers!")
endif()

# Manually find Argon2 components since Config file is missing
find_path(ARGON2_INCLUDE_DIR NAMES argon2.h PATHS ${CMAKE_PREFIX_PATH}/include REQUIRED)
if (ARGON2_INCLUDE_DIR)
    message(STATUS "Found Argon2 headers at: ${ARGON2_INCLUDE_DIR}")
else()
    message(FATAL_ERROR "Could not find Argon2 headers (argon2.h)!")
endif()

find_library(ARGON2_LIBRARY NAMES argon2 libargon2 # Common library names
                             PATHS ${CMAKE_PREFIX_PATH}/lib ${CMAKE_PREFIX_PATH}/lib/manual-link # Search vcpkg lib dirs
                             REQUIRED)
if (ARGON2_LIBRARY)
    message(STATUS "Found Argon2 library at: ${ARGON2_LIBRARY}")
else()
    message(FATAL_ERROR "Could not find Argon2 library (libargon2.lib / argon2.lib)!")
endif()
# --- End Find Packages ---

# --- Conditional Boost Logic (if C++14 is potentially used) ---
if (CMAKE_CXX_STANDARD LESS 17)
    message(STATUS "C++14 requires Boost. Finding Boost...")
    find_package(Boost 1.61.0 REQUIRED) # Ensure Boost is installed via vcpkg if needed
    message(STATUS "Found Boost")
elseif (CMAKE_CXX_STANDARD LESS 20)
    message(STATUS "Using C++17")
else ()
    message(STATUS "Using C++20")
endif ()
# --- End Conditional Boost Logic ---

# --- Executable Definition ---
# The main executable target
add_executable(${PROJECT_NAME} main.cc)

# --- Source Files ---
# Explicitly list all source files (besides main.cc)
# Adjust paths if your structure is different (e.g., models/src/)
set(MODEL_SOURCES
    models/Users.cc
    models/ActiveSessions.cc
)
set(CONTROLLER_SOURCES
    controllers/AuthController.cc
    controllers/AskController.cc    
    controllers/AdminController.cc  
)
set(FILTER_SOURCES
    filters/JwtFilter.cc 
    # Add filter .cc files here if/when you create them
    # Example: filters/JwtFilter.cc
)
set(PLUGIN_SOURCES
    # Add plugin .cc files here if/when you create them
)

target_sources(${PROJECT_NAME}
               PRIVATE
               ${MODEL_SOURCES}
               ${CONTROLLER_SOURCES}
               ${FILTER_SOURCES}
               ${PLUGIN_SOURCES}
               )

# --- Drogon Views Creation ---
# Generates C++ headers from .csp view files
# Adjust path to views directory if needed
drogon_create_views(${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/views
                    ${CMAKE_CURRENT_BINARY_DIR})
# --- End Drogon Views Creation ---

# --- Include Directories ---
# Tell the compiler where to find header files
target_include_directories(${PROJECT_NAME}
                           PRIVATE
                                   ${CMAKE_CURRENT_SOURCE_DIR} # Include project root
                                   ${CMAKE_CURRENT_SOURCE_DIR}/models # Include models directory
                                   ${JWT_CPP_INCLUDE_DIRS} # Include path found for jwt-cpp
                                   ${ARGON2_INCLUDE_DIR}   # Include path found for Argon2
                                   # Include paths for Drogon, PostgreSQL, OpenSSL, JsonCpp
                                   # should be automatically added by linking their targets below.
                           )

# --- Compile Definitions ---
# Apply NOMINMAX definition for Windows builds to avoid min/max macro conflicts
if(WIN32)
    target_compile_definitions(${PROJECT_NAME} PRIVATE NOMINMAX)
endif()

# --- Link Libraries ---
# Link the executable against all required libraries
target_link_libraries(${PROJECT_NAME} PRIVATE
    Drogon::Drogon              # Drogon framework target
    PostgreSQL::PostgreSQL      # PostgreSQL client (libpq) target
    OpenSSL::SSL                # OpenSSL targets
    OpenSSL::Crypto
    JsonCpp::JsonCpp            # JsonCpp target
    ${ARGON2_LIBRARY}           # Link the found Argon2 library file
    # No specific link target needed for header-only jwt-cpp via vcpkg find_path
)

# Conditionally link Boost library if using C++14
if (CMAKE_CXX_STANDARD LESS 17)
    target_link_libraries(${PROJECT_NAME} PRIVATE Boost::boost)
endif()
# --- End Link Libraries ---

# --- Optional: Testing Subdirectory ---
# If you have tests in a 'test' subdirectory with its own CMakeLists.txt:
# add_subdirectory(test)

# --- Optional: Dynamic View Loading Settings ---
# Uncomment the following lines if you want Drogon to load/compile views at runtime
# set_property(TARGET ${PROJECT_NAME} PROPERTY ENABLE_EXPORTS ON)
# target_compile_definitions(${PROJECT_NAME} PRIVATE USE_DYNAMIC_VIEWS)
# message(STATUS "Dynamic view loading enabled.")