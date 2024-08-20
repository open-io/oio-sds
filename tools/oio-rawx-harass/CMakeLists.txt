add_custom_target(oio-rawx-harass ALL)

add_custom_command(
	TARGET oio-rawx-harass
	COMMENT "Build oio-rawx-harass tool, a rawx stress test written in Golang"
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/client/rawx_client.go
		${CMAKE_CURRENT_SOURCE_DIR}/client/stats.go
		${CMAKE_CURRENT_SOURCE_DIR}/client/targets.go
		${CMAKE_CURRENT_SOURCE_DIR}/main.go
		${CMAKE_CURRENT_SOURCE_DIR}/scenario/batch/config.go
		${CMAKE_CURRENT_SOURCE_DIR}/scenario/batch/population.go
		${CMAKE_CURRENT_SOURCE_DIR}/scenario/cycle/behavior.go
		${CMAKE_CURRENT_SOURCE_DIR}/scenario/cycle/config.go
		${CMAKE_CURRENT_SOURCE_DIR}/scenario/cycle/population.go
		${CMAKE_CURRENT_SOURCE_DIR}/scenario/proba/behavior.go
		${CMAKE_CURRENT_SOURCE_DIR}/scenario/proba/builders.go
		${CMAKE_CURRENT_SOURCE_DIR}/scenario/proba/config.go
		${CMAKE_CURRENT_SOURCE_DIR}/scenario/proba/heap.go
		${CMAKE_CURRENT_SOURCE_DIR}/scenario/proba/heap_test.go
		${CMAKE_CURRENT_SOURCE_DIR}/scenario/proba/population.go
		${CMAKE_CURRENT_SOURCE_DIR}/scenario/proba/size_histograms.go
		${CMAKE_CURRENT_SOURCE_DIR}/scenario/runnable.go
		${CMAKE_CURRENT_SOURCE_DIR}/utils/macros.go
		${CMAKE_CURRENT_SOURCE_DIR}/utils/randstr.go
		${CMAKE_CURRENT_SOURCE_DIR}/utils/repeater.go
		${CMAKE_CURRENT_SOURCE_DIR}/go.sum
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	COMMAND ${GO_EXECUTABLE} ARGS vet .
	COMMAND ${GO_EXECUTABLE} ARGS build -o ${CMAKE_CURRENT_BINARY_DIR}/oio-rawx-harass .
)

add_custom_target(oio-rawx-harass-agent ALL)

add_custom_command(
	TARGET oio-rawx-harass-agent
	COMMENT "Build oio-rawx-harass-agent, listing rawx chunks"
	DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/agent/main.go
        ${CMAKE_CURRENT_SOURCE_DIR}/utils/macros.go
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/agent
    COMMAND ${GO_EXECUTABLE} ARGS vet .
    COMMAND ${GO_EXECUTABLE} ARGS build -o ${CMAKE_CURRENT_BINARY_DIR}/oio-rawx-harass-agent .
)

install(PROGRAMS
		${CMAKE_CURRENT_BINARY_DIR}/oio-rawx-harass
		${CMAKE_CURRENT_BINARY_DIR}/oio-rawx-harass-agent
	DESTINATION bin)

