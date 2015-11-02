add_definitions(-DG_LOG_DOMAIN="oio.utils")

include_directories(BEFORE . ../..
		${CMAKE_CURRENT_BINARY_DIR}/../..
		${CMAKE_CURRENT_BINARY_DIR})

link_directories(
		${ASN1C_LIBRARY_DIRS})

include_directories(AFTER
		${JSONC_INCLUDE_DIRS})

add_custom_command(
	OUTPUT
		NativeEnumerated.c NativeEnumerated.h
		NativeInteger.c NativeInteger.h
		OCTET_STRING.c OCTET_STRING.h
		PrintableString.c PrintableString.h
		BIT_STRING.c BIT_STRING.h
		BOOLEAN.c BOOLEAN.h
		INTEGER.c INTEGER.h
		REAL.c REAL.h
		asn_application.h asn_codecs.h asn_codecs_prim.c asn_codecs_prim.h asn_internal.h

		AddrInfo.c AddrInfo.h AddrInfoSequence.c AddrInfoSequence.h
		ChunkId.c ChunkId.h
		ChunkInfo.c ChunkInfo.h ChunkInfoSequence.c ChunkInfoSequence.h
		ContentList.c ContentList.h
		Message.c Message.h
		Meta0Info.c Meta0Info.h Meta0InfoSequence.c Meta0InfoSequence.h
		Meta2Property.c Meta2Property.h Meta2PropertySequence.c Meta2PropertySequence.h
		NamespaceInfoValueList.c NamespaceInfoValueList.h NamespaceInfo.c NamespaceInfo.h NamespaceInfoSequence.c NamespaceInfoSequence.h
		Parameter.c Parameter.h ParameterSequence.c ParameterSequence.h
		Score.c Score.h
		ServiceInfo.c ServiceInfo.h ServiceInfoSequence.c ServiceInfoSequence.h
		ServiceTag.c ServiceTag.h

		RowFieldValue.c RowFieldValue.h
		RowField.c RowField.h
		RowFieldSequence.c RowFieldSequence.h
		RowFieldType.c RowFieldType.h
		Row.c Row.h
		RowSet.c RowSet.h
		RowName.c RowName.h
		TableHeader.c TableHeader.h
		Table.c Table.h
		TableSequence.c TableSequence.h
		TableVersion.c TableVersion.h
		BaseVersion.c BaseVersion.h

		M2V2Alias.c M2V2Alias.h
		M2V2Bean.c M2V2Bean.h
		M2V2BeanSequence.c M2V2BeanSequence.h
		M2V2Chunk.c M2V2Chunk.h
		M2V2ContentHeader.c M2V2ContentHeader.h
		M2V2Property.c M2V2Property.h

	PRE_BUILD
	COMMAND ${ASN1C_EXECUTABLE} ${ASN1C_EXE_OPTS} -fcompound-names -fskeletons-copy ${CMAKE_CURRENT_SOURCE_DIR}/description.asn
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/description.asn
	COMMENT "Generating asn1c types"
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/description.asn
)

add_custom_command(
	OUTPUT expr.yacc.c expr.yacc.h
	COMMAND ${BISON_EXECUTABLE}
	ARGS -d -y -o expr.yacc.c ${CMAKE_CURRENT_SOURCE_DIR}/expr.yacc.y
)

add_custom_command(
	OUTPUT expr.lex.c
	COMMAND ${FLEX_EXECUTABLE}
	ARGS -s -oexpr.lex.c ${CMAKE_CURRENT_SOURCE_DIR}/expr.lex.l
	DEPENDS expr.yacc.c expr.yacc.h
)

#	ARGS -d -s -oexpr.lex.c ${CMAKE_CURRENT_SOURCE_DIR}/expr.lex.l

add_library(metautils SHARED
		metacomm.h
		metatypes.h
		metautils.h
		metautils_bits.h
		metautils_macros.h

		volume_lock.c volume_lock.h
		lb.c lb.h
		common_main.c common_main.h
		utils_syscall.c metautils_syscall.h
		lrutree.c lrutree.h tree.h
		cache.c cache.h
		storage_policy.c storage_policy.h
		expr.2str.c
		expr.clean.c
		expr.eval.c
		expr.lex.c expr.yacc.c expr.yacc.h
		expr.h

		utils_containers.c metautils_containers.h
		utils_svc_policy.c metautils_svc_policy.h
		utils_errors.c metautils_errors.h
		utils_sockets.c metautils_sockets.h
		utils_strings.c metautils_strings.h
		utils_hashstr.c metautils_hashstr.h
		utils_resolv.c metautils_resolv.h
		utils_task.c metautils_task.h
		utils_addr_info.c
		utils_hash.c
		utils_gba.c
		utils_kv.c
		utils_acl.c
		utils_l4v.c
		utils_m1url.c
		utils_meta0_info.c
		utils_metadata.c
		utils_namespace_info.c
		utils_service_info.c
		utils_tools.c
		utils_duplication.c

		gridd_client.c gridd_client.h
		gridd_client_ext.c gridd_client_ext.h
		gridd_client_pool.c gridd_client_pool.h

		${CMAKE_CURRENT_BINARY_DIR}/NativeEnumerated.c
		${CMAKE_CURRENT_BINARY_DIR}/NativeEnumerated.h
		${CMAKE_CURRENT_BINARY_DIR}/NativeInteger.c
		${CMAKE_CURRENT_BINARY_DIR}/NativeInteger.h
		${CMAKE_CURRENT_BINARY_DIR}/OCTET_STRING.c
		${CMAKE_CURRENT_BINARY_DIR}/OCTET_STRING.h
		${CMAKE_CURRENT_BINARY_DIR}/PrintableString.c
		${CMAKE_CURRENT_BINARY_DIR}/PrintableString.h
		${CMAKE_CURRENT_BINARY_DIR}/BIT_STRING.c
		${CMAKE_CURRENT_BINARY_DIR}/BIT_STRING.h
		${CMAKE_CURRENT_BINARY_DIR}/BOOLEAN.c
		${CMAKE_CURRENT_BINARY_DIR}/BOOLEAN.h
		${CMAKE_CURRENT_BINARY_DIR}/INTEGER.c
		${CMAKE_CURRENT_BINARY_DIR}/INTEGER.h
		${CMAKE_CURRENT_BINARY_DIR}/REAL.c
		${CMAKE_CURRENT_BINARY_DIR}/REAL.h

		${CMAKE_CURRENT_BINARY_DIR}/asn_application.h
		${CMAKE_CURRENT_BINARY_DIR}/asn_codecs.h
		${CMAKE_CURRENT_BINARY_DIR}/asn_codecs_prim.c
		${CMAKE_CURRENT_BINARY_DIR}/asn_codecs_prim.h
		${CMAKE_CURRENT_BINARY_DIR}/asn_internal.h

		${CMAKE_CURRENT_BINARY_DIR}/AddrInfo.c
		${CMAKE_CURRENT_BINARY_DIR}/AddrInfo.h
		${CMAKE_CURRENT_BINARY_DIR}/AddrInfoSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/AddrInfoSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/ChunkId.c
		${CMAKE_CURRENT_BINARY_DIR}/ChunkId.h
		${CMAKE_CURRENT_BINARY_DIR}/ChunkInfo.c
		${CMAKE_CURRENT_BINARY_DIR}/ChunkInfo.h
		${CMAKE_CURRENT_BINARY_DIR}/ChunkInfoSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/ChunkInfoSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/ContentList.c
		${CMAKE_CURRENT_BINARY_DIR}/ContentList.h
		${CMAKE_CURRENT_BINARY_DIR}/Message.c
		${CMAKE_CURRENT_BINARY_DIR}/Message.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta0Info.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta0Info.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta0InfoSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta0InfoSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta2Property.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta2Property.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta2PropertySequence.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta2PropertySequence.h
		${CMAKE_CURRENT_BINARY_DIR}/NamespaceInfoValueList.c
		${CMAKE_CURRENT_BINARY_DIR}/NamespaceInfoValueList.h
		${CMAKE_CURRENT_BINARY_DIR}/NamespaceInfo.c
		${CMAKE_CURRENT_BINARY_DIR}/NamespaceInfo.h
		${CMAKE_CURRENT_BINARY_DIR}/NamespaceInfoSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/NamespaceInfoSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/Parameter.c
		${CMAKE_CURRENT_BINARY_DIR}/Parameter.h
		${CMAKE_CURRENT_BINARY_DIR}/ParameterSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/ParameterSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/Score.c
		${CMAKE_CURRENT_BINARY_DIR}/Score.h
		${CMAKE_CURRENT_BINARY_DIR}/ServiceInfo.c
		${CMAKE_CURRENT_BINARY_DIR}/ServiceInfo.h
		${CMAKE_CURRENT_BINARY_DIR}/ServiceInfoSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/ServiceInfoSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/ServiceTag.c
		${CMAKE_CURRENT_BINARY_DIR}/ServiceTag.h

		${CMAKE_CURRENT_BINARY_DIR}/RowFieldSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/RowFieldSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/RowFieldValue.c
		${CMAKE_CURRENT_BINARY_DIR}/RowFieldValue.h
		${CMAKE_CURRENT_BINARY_DIR}/RowFieldType.c
		${CMAKE_CURRENT_BINARY_DIR}/RowFieldType.h
		${CMAKE_CURRENT_BINARY_DIR}/RowField.c
		${CMAKE_CURRENT_BINARY_DIR}/RowField.h
		${CMAKE_CURRENT_BINARY_DIR}/Row.c
		${CMAKE_CURRENT_BINARY_DIR}/Row.h
		${CMAKE_CURRENT_BINARY_DIR}/RowSet.c
		${CMAKE_CURRENT_BINARY_DIR}/RowSet.h
		${CMAKE_CURRENT_BINARY_DIR}/RowName.c
		${CMAKE_CURRENT_BINARY_DIR}/RowName.h
		${CMAKE_CURRENT_BINARY_DIR}/TableHeader.c
		${CMAKE_CURRENT_BINARY_DIR}/TableHeader.h
		${CMAKE_CURRENT_BINARY_DIR}/Table.c
		${CMAKE_CURRENT_BINARY_DIR}/Table.h
		${CMAKE_CURRENT_BINARY_DIR}/TableSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/TableSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/TableVersion.c
		${CMAKE_CURRENT_BINARY_DIR}/TableVersion.h
		${CMAKE_CURRENT_BINARY_DIR}/BaseVersion.c
		${CMAKE_CURRENT_BINARY_DIR}/BaseVersion.h

		${CMAKE_CURRENT_BINARY_DIR}/M2V2BeanSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/M2V2BeanSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/M2V2Bean.h
		${CMAKE_CURRENT_BINARY_DIR}/M2V2Bean.c
		${CMAKE_CURRENT_BINARY_DIR}/M2V2Alias.h
		${CMAKE_CURRENT_BINARY_DIR}/M2V2Alias.c
		${CMAKE_CURRENT_BINARY_DIR}/M2V2Chunk.h
		${CMAKE_CURRENT_BINARY_DIR}/M2V2Chunk.c
		${CMAKE_CURRENT_BINARY_DIR}/M2V2ContentHeader.h
		${CMAKE_CURRENT_BINARY_DIR}/M2V2ContentHeader.c
		${CMAKE_CURRENT_BINARY_DIR}/M2V2Property.h
		${CMAKE_CURRENT_BINARY_DIR}/M2V2Property.c

		comm_message.c
		comm_converter.c
		comm_meta_reply.c
)

target_link_libraries(metautils
		oiocore
		${GLIB2_LIBRARIES} ${JSONC_LIBRARIES}
		${ASN1C_LIBRARIES}
		-lm)

#add_dependencies(metautils asn1c_generation)

add_executable(test_lb test_lb.c)
target_link_libraries(test_lb
		metautils
		${GLIB2_LIBRARIES})

add_executable(test_stg_policy test_stg_policy.c)
target_link_libraries(test_stg_policy
		metautils
		${GLIB2_LIBRARIES})

add_executable(test_svc_policy test_svc_policy.c)
target_link_libraries(test_svc_policy
		metautils
		${GLIB2_LIBRARIES})

add_executable(test_logger test_logger.c)
target_link_libraries(test_logger
		metautils ${GLIB2_LIBRARIES})

add_executable(test_addr test_addr.c)
target_link_libraries(test_addr
		metautils
		${GLIB2_LIBRARIES})

add_executable(test_gridd_client test_gridd_client.c)
target_link_libraries(test_gridd_client
		metautils
		${GLIB2_LIBRARIES})

add_executable(test_lrutree test_lrutree.c)
target_link_libraries(test_lrutree
		metautils
		${GLIB2_LIBRARIES})

add_executable(test_sigfpe test_sigfpe.c)
target_link_libraries(test_sigfpe
		metautils
		${GLIB2_LIBRARIES})

add_executable(test_str test_str.c)
target_link_libraries(test_str
		metautils
		${GLIB2_LIBRARIES})

add_executable(test_gba test_gba.c)
target_link_libraries(test_gba
		metautils
		${GLIB2_LIBRARIES})

install(TARGETS metautils
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin
		PUBLIC_HEADER DESTINATION include)

install(FILES
			common_main.h
			expr.h
			gridd_client.h
			gridd_client_ext.h
			gridd_client_pool.h
			cache.h
			lb.h
			lrutree.h
			metacomm.h
			metatype_acl.h
			metatype_addrinfo.h
			metatype_cid.h
			metatype_kv.h
			metatype_m0info.h
			metatype_m1url.h
			metatype_metadata.h
			metatype_nsinfo.h
			metatypes.h
			metatype_srvinfo.h
			metautils_bits.h
			metautils_containers.h
			metautils-doc.h
			metautils_errors.h
			metautils_gba.h
			metautils.h
			metautils_hashstr.h
			metautils_l4v.h
			metautils_macros.h
			metautils_resolv.h
			metautils_sockets.h
			metautils_strings.h
			metautils_svc_policy.h
			metautils_syscall.h
			metautils_task.h
			storage_policy.h
			test_addr.h
			tree.h
			volume_lock.h
		DESTINATION include/metautils/lib
		PERMISSIONS
			OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)


add_test(NAME metautils/stgpol COMMAND test_stg_policy)
add_test(NAME metautils/svc_policy COMMAND test_svc_policy)
add_test(NAME metautils/lb COMMAND test_lb)
add_test(NAME metautils/logger COMMAND test_logger)
add_test(NAME metautils/lru COMMAND test_lrutree)
add_test(NAME metautils/addr COMMAND test_addr)
add_test(NAME metautils/gridd_client COMMAND test_gridd_client)
#add_test(NAME metautils/sigfpe COMMAND test_sigfpe)
add_test(NAME metautils/strings COMMAND test_str)
add_test(NAME metautils/gba COMMAND test_gba)

