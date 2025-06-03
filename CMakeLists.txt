cmake_minimum_required(VERSION 3.10) # Increased slightly for better pkg-config etc.
project(chatbot_admin_backend CXX)

include(CheckIncludeFileCXX)

# --- C++ Standard Detection Logic ---
# (Keep your existing C++ standard detection logic, it's good)
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

# --- Find System Packages ---
find_package(Drogon REQUIRED CONFIG) # Drogon usually installs CMake config files even if built from source
                                     # If not, you might need pkg_check_modules or manual find.

find_package(PkgConfig REQUIRED)   # Utility for .pc files

pkg_check_modules(PGSQL REQUIRED libpq)
pkg_check_modules(OPENSSL REQUIRED openssl) # This usually finds libssl and libcrypto via openssl.pc
                                         # If not, you might need:
                                         # pkg_check_modules(SSL REQUIRED libssl)
                                         # pkg_check_modules(CRYPTO REQUIRED libcrypto)

message(STATUS "DEBUG: --- Preparing to search for JsonCpp ---")
message(STATUS "DEBUG: CMAKE_PREFIX_PATH is: '${CMAKE_PREFIX_PATH}'")
message(STATUS "DEBUG: CMAKE_MODULE_PATH is: '${CMAKE_MODULE_PATH}'")
message(STATUS "DEBUG: JsonCpp_DIR is: '${JsonCpp_DIR}'")
set(CMAKE_FIND_DEBUG_MODE TRUE)

find_package(JsonCpp REQUIRED CONFIG)   # libjsoncpp-dev provides JsonCppConfig.cmake

pkg_check_modules(ARGON2 REQUIRED libargon2) # libargon2-dev provides libargon2.pc

# Find header-only jwt-cpp using find_path
# Option 1: Assume it's in a subdirectory of your project (e.g., vendor/jwt-cpp or lib/jwt-cpp)
find_path(JWT_CPP_INCLUDE_DIRS NAMES "jwt-cpp/jwt.h" # This is the <path>/<file_name> to find
                         PATHS ${CMAKE_CURRENT_SOURCE_DIR}/vendor/jwt-cpp/include # Search this directory
                         REQUIRED NO_DEFAULT_PATH NO_CMAKE_ENVIRONMENT_PATH NO_CMAKE_PATH NO_SYSTEM_ENVIRONMENT_PATH NO_CMAKE_SYSTEM_PATH)# Option 2: Or expect it to be installed in system include paths (less common for direct project usage)
find_path(JWT_CPP_INCLUDE_DIRS NAMES "jwt-cpp/jwt.h" REQUIRED) # Searches default include paths

if (JWT_CPP_INCLUDE_DIRS)
    message(STATUS "Found jwt-cpp headers at: ${JWT_CPP_INCLUDE_DIRS}")
else()
    message(FATAL_ERROR "Could not find jwt-cpp headers! Make sure it's in your project or system include path.")
endif()
# --- End Find Packages ---

# --- Conditional Boost Logic (if C++14 is potentially used) ---
if (CMAKE_CXX_STANDARD LESS 17)
    message(STATUS "C++14 might require Boost. Finding Boost...")
    # Boost from apt (libboost-dev) typically provides CMake config files
    find_package(Boost 1.61.0) # Make it non-REQUIRED initially
    if(Boost_FOUND)
        message(STATUS "Found Boost version ${Boost_VERSION}")
    else()
        message(WARNING "Boost not found. If your C++14 code relies on Boost features not in the std lib, this might fail.")
        # Or make it FATAL_ERROR if Boost is strictly necessary for C++14 path
        # message(FATAL_ERROR "Boost 1.61.0 or newer required for C++14 features but not found.")
    endif()
elseif (CMAKE_CXX_STANDARD LESS 20)
    message(STATUS "Using C++17")
else ()
    message(STATUS "Using C++20")
endif ()
# --- End Conditional Boost Logic ---

# --- Executable Definition ---
add_executable(${PROJECT_NAME} main.cc)

# --- Source Files ---
# (Keep your existing MODEL_SOURCES, CONTROLLER_SOURCES, etc. definitions)
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
)
set(PLUGIN_SOURCES
)

target_sources(${PROJECT_NAME}
               PRIVATE
               ${MODEL_SOURCES}
               ${CONTROLLER_SOURCES}
               ${FILTER_SOURCES}
               ${PLUGIN_SOURCES}
               )

# --- Drogon Views Creation ---
drogon_create_views(${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/views
                    ${CMAKE_CURRENT_BINARY_DIR})
# --- End Drogon Views Creation ---

# --- Include Directories ---
target_include_directories(${PROJECT_NAME}
                           PRIVATE
                                   ${CMAKE_CURRENT_SOURCE_DIR}
                                   ${CMAKE_CURRENT_SOURCE_DIR}/models
                                   ${JWT_CPP_INCLUDE_DIRS}
                                   # Include paths from pkg_check_modules
                                   ${PGSQL_INCLUDE_DIRS}
                                   ${OPENSSL_INCLUDE_DIRS}
                                   # ${SSL_INCLUDE_DIRS} # If using separate pkg_check_modules for libssl
                                   # ${CRYPTO_INCLUDE_DIRS} # If using separate pkg_check_modules for libcrypto
                                   ${ARGON2_INCLUDE_DIRS}
                                   # Drogon and JsonCpp include dirs should be handled by linking their imported targets
                           )

# --- Compile Definitions ---
if(WIN32) # This block will likely not be hit on Ubuntu but harmless to keep
    target_compile_definitions(${PROJECT_NAME} PRIVATE NOMINMAX)
endif()

# --- Link Libraries ---
target_link_libraries(${PROJECT_NAME} PRIVATE
    Drogon::Drogon              # Drogon framework imported target
    ${PGSQL_LIBRARIES}          # From pkg_check_modules
    ${OPENSSL_LIBRARIES}        # From pkg_check_modules for openssl.pc
    # If using separate pkg_check_modules:
    # ${SSL_LIBRARIES}
    # ${CRYPTO_LIBRARIES}
    JsonCpp::JsonCpp            # JsonCpp imported target from its CMake config
    ${ARGON2_LIBRARIES}         # From pkg_check_modules
)

# Conditionally link Boost library
if (CMAKE_CXX_STANDARD LESS 17 AND Boost_FOUND)
    # Boost::boost is a common imported target name.
    # It might also be specific components like Boost::system, Boost::filesystem
    # depending on what you actually use from Boost.
    # Check Boost's CMake documentation if this general target doesn't work.
    target_link_libraries(${PROJECT_NAME} PRIVATE Boost::boost)
endif()
# --- End Link Libraries ---