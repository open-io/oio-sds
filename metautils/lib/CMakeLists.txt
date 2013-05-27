include_directories(BEFORE .)

link_directories(
		${ASN1C_LIBRARY_DIRS})

include_directories(AFTER
		${OPENSSL_INCLUDE_DIRS})

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
		ArrayList.c ArrayList.h
		ChunkId.c ChunkId.h ChunkIdSequence.c ChunkIdSequence.h
		ChunkInfo.c ChunkInfo.h ChunkInfoSequence.c ChunkInfoSequence.h
		ContainerEvent.c ContainerEvent.h ContainerEventSequence.c ContainerEventSequence.h
		ContentList.c ContentList.h
		EventSequence.c EventSequence.h
		Message.c Message.h
		Meta0Info.c Meta0Info.h Meta0InfoSequence.c Meta0InfoSequence.h
		Meta1Info.c Meta1Info.h Meta1InfoSequence.c Meta1InfoSequence.h
		Meta1RawContainer.c Meta1RawContainer.h
		Meta1Stat.c Meta1Stat.h Meta1StatSequence.c Meta1StatSequence.h
		Meta2Info.c Meta2Info.h Meta2InfoSequence.c Meta2InfoSequence.h
		Meta2Property.c Meta2Property.h Meta2PropertySequence.c Meta2PropertySequence.h
		Meta2RawChunk.c Meta2RawChunk.h Meta2RawChunkSequence.c Meta2RawChunkSequence.h
		Meta2RawContent.c Meta2RawContent.h Meta2RawContentSequence.c Meta2RawContentSequence.h
		Meta2RawContentHeader.c Meta2RawContentHeader.h Meta2RawContentHeaderSequence.c Meta2RawContentHeaderSequence.h
		Meta2RawContentV2.c Meta2RawContentV2.h Meta2RawContentV2Sequence.c Meta2RawContentV2Sequence.h
		Meta2Stat.c Meta2Stat.h Meta2StatSequence.c Meta2StatSequence.h
		NamespaceInfoValueList.c NamespaceInfoValueList.h NamespaceInfo.c NamespaceInfo.h NamespaceInfoSequence.c NamespaceInfoSequence.h
		Parameter.c Parameter.h ParameterSequence.c ParameterSequence.h
		PathInfo.c PathInfo.h PathInfoSequence.c PathInfoSequence.h
		Score.c Score.h
		ServiceInfo.c ServiceInfo.h ServiceInfoSequence.c ServiceInfoSequence.h
		ServiceTag.c ServiceTag.h
		VolumeInfo.c VolumeInfo.h VolumeInfoSequence.c VolumeInfoSequence.h
		VolumeStat.c VolumeStat.h
		VolumeStatSequence.c VolumeStatSequence.h
		ContainerInfoSequence.c ContainerInfoSequence.h
		ContainerInfo.c ContainerInfo.h

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
		M2V2Content.c M2V2Content.h
		M2V2ContentHeader.c M2V2ContentHeader.h
		M2V2Property.c M2V2Property.h

	PRE_BUILD
	COMMAND ${ASN1C_EXECUTABLE} -fcompound-names -fskeletons-copy ${CMAKE_CURRENT_SOURCE_DIR}/description.asn
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
		lrutree.c lrutree.h tree.h
		storage_policy.h storage_policy.c
		hc_url.h hc_url.c
		expr.2str.c
		expr.clean.c
		expr.eval.c
		expr.lex.c expr.yacc.c expr.yacc.h
		expr.h
		metacomm.h
		metatypes.h
		metautils.h
		metautils_internals.h
		gs_manifest.h
		hashstr.h
		loggers.h
		volume_lock.h
		utils_addr_info.c
		utils_chunk_info.c
		utils_container_event.c
		utils_hash.c
		utils_gba.c
		utils_kv.c
		utils_acl.c
		utils_l4v.c
		utils_meta0_info.c
		utils_meta1_info.c
		utils_meta1_raw_container.c
		utils_meta1_stat.c
		utils_meta2_info.c
		utils_meta2_maintenance.c
		utils_meta2_stat.c
		utils_metadata.c
		utils_manifest.c
		utils_namespace_info.c
		utils_path_info.c
		utils_rawx_maintenance.c
		utils_score.c
		utils_service_info.c
		utils_tools.c
		utils_volume_info.c
		utils_volume_stat.c
		utils_duplication.c
		hashstr.c
		volume_lock.c
		loggers.c
		resolv.c resolv.h
		common_main.c common_main.h
		lb.c lb.h
		svc_policy.c svc_policy.h
)

target_link_libraries(metautils
		${OPENSSL_LIBRARIES} ${GLIB2_LIBRARIES} -lm -lexpat)

set_target_properties(metautils PROPERTIES SOVERSION ${ABI_VERSION})

add_dependencies(metautils asn1c_generation)

add_library(metacomm SHARED
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
		${CMAKE_CURRENT_BINARY_DIR}/ArrayList.c
		${CMAKE_CURRENT_BINARY_DIR}/ArrayList.h
		${CMAKE_CURRENT_BINARY_DIR}/ChunkId.c
		${CMAKE_CURRENT_BINARY_DIR}/ChunkId.h
		${CMAKE_CURRENT_BINARY_DIR}/ChunkIdSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/ChunkIdSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/ChunkInfo.c
		${CMAKE_CURRENT_BINARY_DIR}/ChunkInfo.h
		${CMAKE_CURRENT_BINARY_DIR}/ChunkInfoSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/ChunkInfoSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/ContainerEvent.c
		${CMAKE_CURRENT_BINARY_DIR}/ContainerEvent.h
		${CMAKE_CURRENT_BINARY_DIR}/ContainerEventSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/ContainerEventSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/ContentList.c
		${CMAKE_CURRENT_BINARY_DIR}/ContentList.h
		${CMAKE_CURRENT_BINARY_DIR}/EventSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/EventSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/Message.c
		${CMAKE_CURRENT_BINARY_DIR}/Message.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta0Info.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta0Info.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta0InfoSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta0InfoSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta1Info.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta1Info.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta1InfoSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta1InfoSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta1RawContainer.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta1RawContainer.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta1Stat.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta1Stat.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta1StatSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta1StatSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta2Info.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta2Info.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta2InfoSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta2InfoSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta2Property.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta2Property.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta2PropertySequence.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta2PropertySequence.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta2RawChunk.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta2RawChunk.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta2RawChunkSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta2RawChunkSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta2RawContent.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta2RawContent.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta2RawContentSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta2RawContentSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta2RawContentHeader.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta2RawContentHeader.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta2RawContentHeaderSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta2RawContentHeaderSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta2RawContentV2.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta2RawContentV2.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta2RawContentV2Sequence.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta2RawContentV2Sequence.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta2Stat.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta2Stat.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta2StatSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta2StatSequence.h
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
		${CMAKE_CURRENT_BINARY_DIR}/PathInfo.c
		${CMAKE_CURRENT_BINARY_DIR}/PathInfo.h
		${CMAKE_CURRENT_BINARY_DIR}/PathInfoSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/PathInfoSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/Score.c
		${CMAKE_CURRENT_BINARY_DIR}/Score.h
		${CMAKE_CURRENT_BINARY_DIR}/ServiceInfo.c
		${CMAKE_CURRENT_BINARY_DIR}/ServiceInfo.h
		${CMAKE_CURRENT_BINARY_DIR}/ServiceInfoSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/ServiceInfoSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/ServiceTag.c
		${CMAKE_CURRENT_BINARY_DIR}/ServiceTag.h
		${CMAKE_CURRENT_BINARY_DIR}/VolumeInfo.c
		${CMAKE_CURRENT_BINARY_DIR}/VolumeInfo.h
		${CMAKE_CURRENT_BINARY_DIR}/VolumeInfoSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/VolumeInfoSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/VolumeStat.c
		${CMAKE_CURRENT_BINARY_DIR}/VolumeStat.h
		${CMAKE_CURRENT_BINARY_DIR}/VolumeStatSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/VolumeStatSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/ContainerInfoSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/ContainerInfoSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/ContainerInfo.c
		${CMAKE_CURRENT_BINARY_DIR}/ContainerInfo.h

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
		${CMAKE_CURRENT_BINARY_DIR}/M2V2Content.h
		${CMAKE_CURRENT_BINARY_DIR}/M2V2Content.c
		${CMAKE_CURRENT_BINARY_DIR}/M2V2Chunk.h
		${CMAKE_CURRENT_BINARY_DIR}/M2V2Chunk.c
		${CMAKE_CURRENT_BINARY_DIR}/M2V2ContentHeader.h
		${CMAKE_CURRENT_BINARY_DIR}/M2V2ContentHeader.c
		${CMAKE_CURRENT_BINARY_DIR}/M2V2Property.h
		${CMAKE_CURRENT_BINARY_DIR}/M2V2Property.c

		asn_AddrInfo.c
		asn_AddrInfo.h
		asn_ChunkInfo.c
		asn_ChunkInfo.h
		asn_ContainerEvent.c
		asn_ContainerEvent.h
		asn_Integer.c
		asn_Integer.h
		asn_Meta0Info.c asn_Meta0Info.h
		asn_Meta1Info.c asn_Meta1Info.h
		asn_Meta1Stat.c asn_Meta1Stat.h
		asn_Meta2Info.c asn_Meta2Info.h
		asn_Meta2Raw.c asn_Meta2Raw.h
		asn_Meta2Stat.c asn_Meta2Stat.h
		asn_NamespaceInfo.c asn_NamespaceInfo.h
		asn_Parameter.c asn_Parameter.h
		asn_PathInfo.c asn_PathInfo.h
		asn_Score.c asn_Score.h
		asn_ServiceInfo.h
		asn_VolumeInfo.c asn_VolumeInfo.h
		asn_VolumeStat.c asn_VolumeStat.h
		asn_ContainerInfo.c asn_ContainerInfo.h

		comm_abstract_sequence.c
		comm_addr_info.c
		comm_chunk_info.c
		comm_container_event.c
		comm_integer.c
		comm_message.c
		comm_meta0_info.c
		comm_meta1_info.c
		comm_meta1_raw_container.c
		comm_meta1_stat.c
		comm_meta2_info.c
		comm_meta2_maintenance.c
		comm_meta2_stat.c
		comm_meta_reply.c
		comm_namespace_info.c
		comm_parameter.c
		comm_path_info.c
		comm_service_info.c
		comm_volume_info.c
		comm_volume_stat.c
		comm_container_info.c

		gridd_client.c gridd_client.h
)

include_directories(AFTER ${CMAKE_CURRENT_BINARY_DIR})
set_target_properties(metacomm PROPERTIES SOVERSION ${ABI_VERSION})
target_link_libraries(metacomm
		metautils
		${OPENSSL_LIBRARIES} ${GLIB2_LIBRARIES} -lASN1)
add_dependencies(metacomm metautils)

add_executable(redc-oid2cid oid_to_cid.c)
target_link_libraries(redc-oid2cid
		metautils
		${OPENSSL_LIBRARIES} ${GLIB2_LIBRARIES})
add_dependencies(redc-oid2cid metacomm metautils)

add_executable(redc-dump-addr addr_dump.c)
target_link_libraries(redc-dump-addr
		metautils metacomm
		${OPENSSL_LIBRARIES} ${GLIB2_LIBRARIES})

add_executable(gs_same_hash gs_same_hash.c)
target_link_libraries(gs_same_hash
		metautils 
		${OPENSSL_LIBRARIES} ${GLIB2_LIBRARIES})

add_executable(test_lb test_lb.c)
target_link_libraries(test_lb
		metautils metacomm
		${GLIB2_LIBRARIES})

add_executable(test_svc_policy test_svc_policy.c)
target_link_libraries(test_svc_policy
		metautils 
		${GLIB2_LIBRARIES})

add_executable(test_logger test_logger.c)
target_link_libraries(test_logger
		metautils ${GLIB2_LIBRARIES})

add_executable(test_hc_url test_hc_url.c)
target_link_libraries(test_hc_url
		metautils 
		${GLIB2_LIBRARIES})

add_executable(test_lrutree test_lrutree.c)
target_link_libraries(test_lrutree
		metautils 
		${GLIB2_LIBRARIES})

install(TARGETS metacomm metautils redc-oid2cid redc-dump-addr
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin)

add_test(NAME metautils/svc_policy COMMAND test_svc_policy)
add_test(NAME metautils/lb COMMAND test_lb)
add_test(NAME metautils/url COMMAND test_hc_url)

