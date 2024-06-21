add_custom_target(oio-rawx-harass ALL)

set(GO_BUILD_RAWX_HARASS ${GO_EXECUTABLE} build -o ${CMAKE_CURRENT_BINARY_DIR}/oio-rawx-harass .)

add_custom_command(
	TARGET oio-rawx-harass
	DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/main.go
        ${CMAKE_CURRENT_SOURCE_DIR}/scenario/proba/population.go
        ${CMAKE_CURRENT_SOURCE_DIR}/scenario/proba/behavior.go
        ${CMAKE_CURRENT_SOURCE_DIR}/scenario/proba/heap.go
        ${CMAKE_CURRENT_SOURCE_DIR}/scenario_put_get_delete.go
        ${CMAKE_CURRENT_SOURCE_DIR}/client/rawx_client.go
        ${CMAKE_CURRENT_SOURCE_DIR}/utils/randstr.go
	COMMAND
	cd ${CMAKE_CURRENT_SOURCE_DIR} && ${GO_EXECUTABLE} vet . && ${GO_BUILD_RAWX_HARASS}
	COMMENT
		"Build oio-rawx-harass tool, a rawx stress test written in Golang"
)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/oio-rawx-harass
		DESTINATION bin)

