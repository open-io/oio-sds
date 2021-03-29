
add_custom_target(oio-rawx ALL)

set(GO_BUILD ${GO_EXECUTABLE} build -o ${CMAKE_CURRENT_BINARY_DIR}/oio-rawx .)
if ( ENABLE_CODECOVERAGE )
	set(GO_BUILD ${GO_EXECUTABLE} test -c -covermode=count -coverpkg . -o ${CMAKE_CURRENT_BINARY_DIR}/oio-rawx)
	MESSAGE("Building rawx with code coverage support")
endif ( ENABLE_CODECOVERAGE )

add_custom_command(
	TARGET oio-rawx
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/const.go
		${CMAKE_CURRENT_SOURCE_DIR}/chunk_info.go
		${CMAKE_CURRENT_SOURCE_DIR}/chunkrepo.go
		${CMAKE_CURRENT_SOURCE_DIR}/conf_reader.go
		${CMAKE_CURRENT_SOURCE_DIR}/configuration.go
		${CMAKE_CURRENT_SOURCE_DIR}/filerepo.go
		${CMAKE_CURRENT_SOURCE_DIR}/filerepo_test.go
		${CMAKE_CURRENT_SOURCE_DIR}/handler_chunk.go
		${CMAKE_CURRENT_SOURCE_DIR}/handler_stat.go
		${CMAKE_CURRENT_SOURCE_DIR}/hexa.go
		${CMAKE_CURRENT_SOURCE_DIR}/limited_reader.go
		${CMAKE_CURRENT_SOURCE_DIR}/logger.go
		${CMAKE_CURRENT_SOURCE_DIR}/main.go
		${CMAKE_CURRENT_SOURCE_DIR}/notifier.go
		${CMAKE_CURRENT_SOURCE_DIR}/rawx.go
		${CMAKE_CURRENT_SOURCE_DIR}/repo.go
	COMMAND
	cd ${CMAKE_CURRENT_SOURCE_DIR} && ${GO_EXECUTABLE} vet . && ${GO_BUILD}
	COMMENT
		"Build RAWX v2, written in Golang"
)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/oio-rawx
		DESTINATION bin)
