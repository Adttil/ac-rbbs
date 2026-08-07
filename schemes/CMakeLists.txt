function(add_anonymous_credential_scheme scheme)
    file(
        GLOB srcs
        CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/${scheme}/src/*.cpp"
    )

    add_library(${scheme} STATIC ${srcs})

    target_include_directories(
        ${scheme}
        PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/${scheme}/include"
    )

    target_link_libraries(${scheme} PUBLIC crypto12381)
endfunction()

file(
    GLOB scheme_entries
    LIST_DIRECTORIES true
    CONFIGURE_DEPENDS
    RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/*"
)

list(SORT scheme_entries)

set(scheme_names)
foreach(scheme IN LISTS scheme_entries)
    if(IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/${scheme}")
        add_anonymous_credential_scheme(${scheme})
        list(APPEND scheme_names ${scheme})
    endif()
endforeach()

add_library(schemes INTERFACE)
target_include_directories(schemes INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(schemes INTERFACE ${scheme_names})
