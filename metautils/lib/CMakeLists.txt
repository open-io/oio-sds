add_definitions(-DG_LOG_DOMAIN="oio.utils")

include_directories(BEFORE . ../..
		${CMAKE_BINARY_DIR}
		${CMAKE_CURRENT_BINARY_DIR})

link_directories()

include_directories(AFTER
		${JSONC_INCLUDE_DIRS})


add_custom_command(
	OUTPUT
		constraints.c constraints.h
		constr_SET_OF.c constr_SET_OF.h
		constr_SEQUENCE_OF.c constr_SEQUENCE_OF.h
		constr_SEQUENCE.c constr_SEQUENCE.h
		constr_TYPE.c constr_TYPE.h
		constr_CHOICE.c constr_CHOICE.h

		ber_tlv_tag.c ber_tlv_tag.h
		ber_tlv_length.c ber_tlv_length.h
		der_encoder.c der_encoder.h
		ber_decoder.c ber_decoder.h
		xer_support.c xer_support.h
		xer_decoder.c xer_decoder.h
		per_support.c per_support.h
		per_encoder.c per_encoder.h
		xer_encoder.c xer_encoder.h
		per_decoder.c per_decoder.h
		per_opentype.c
		converter-sample.c
		NativeEnumerated.c NativeEnumerated.h
		NativeInteger.c NativeInteger.h
		OCTET_STRING.c OCTET_STRING.h
		PrintableString.c PrintableString.h
		BIT_STRING.c BIT_STRING.h
		BOOLEAN.c BOOLEAN.h
		INTEGER.c INTEGER.h
		ENUMERATED.c ENUMERATED.h
		REAL.c REAL.h
		NULL.c NULL.h

		asn_SEQUENCE_OF.c asn_SEQUENCE_OF.h
		asn_SET_OF.c asn_SET_OF.h
		asn_codecs.h
		asn_codecs_prim.c asn_codecs_prim.h
		asn_internal.h
		asn_system.h
		asn_application.h

		AddrInfo.c AddrInfo.h
		Message.c Message.h
		Meta0Info.c Meta0Info.h
		Meta0InfoSequence.c Meta0InfoSequence.h
		NamespaceInfo.c NamespaceInfo.h
		Parameter.c Parameter.h
		ParameterSequence.c ParameterSequence.h
		Score.c Score.h
		ServiceInfo.c ServiceInfo.h
		ServiceInfoSequence.c ServiceInfoSequence.h
		ServiceTag.c ServiceTag.h

		RowFieldSequence.c RowFieldSequence.h
		RowFieldValue.c RowFieldValue.h
		RowFieldType.c RowFieldType.h
		RowField.c RowField.h
		Row.c Row.h
		RowSet.c RowSet.h
		RowName.c RowName.h
		TableHeader.c TableHeader.h
		Table.c Table.h
		TableSequence.c TableSequence.h
		TableVersion.c TableVersion.h
		BaseVersion.c BaseVersion.h

		M2V2BeanSequence.c M2V2BeanSequence.h
		M2V2Bean.c M2V2Bean.h
		M2V2Alias.c M2V2Alias.h
		M2V2Chunk.c M2V2Chunk.h
		M2V2ContentHeader.c M2V2ContentHeader.h
		M2V2Property.c M2V2Property.h

	PRE_BUILD
	COMMAND
		${ASN1C_EXECUTABLE}
	ARGS
		${ASN1C_EXE_OPTS}
		-fcompound-names
		-fskeletons-copy
		${CMAKE_CURRENT_SOURCE_DIR}/description.asn
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/description.asn
	COMMENT "Generating asn1c types"
)

add_custom_command(
	OUTPUT expr.yacc.c expr.yacc.h
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/expr.yacc.y
	COMMAND ${BISON_EXECUTABLE}
	ARGS -d -y -o expr.yacc.c ${CMAKE_CURRENT_SOURCE_DIR}/expr.yacc.y
)

add_custom_command(
	OUTPUT expr.lex.c
	DEPENDS expr.yacc.c expr.yacc.h
	COMMAND ${FLEX_EXECUTABLE}
	ARGS -s -oexpr.lex.c ${CMAKE_CURRENT_SOURCE_DIR}/expr.lex.l
)

add_custom_command(
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/common_variables.c
		${CMAKE_CURRENT_BINARY_DIR}/common_variables.h
	DEPENDS
		${CMAKE_SOURCE_DIR}/confgen.py
		${CMAKE_SOURCE_DIR}/conf.json
	PRE_BUILD
	COMMENT
		"Generating the central configuration"
	COMMAND
		${PYTHON_EXECUTABLE}
	ARGS
		${CMAKE_SOURCE_DIR}/confgen.py
		"metautils"
		${CMAKE_SOURCE_DIR}/conf.json)

add_library(metautils SHARED
		metacomm.h
		metatypes.h
		metautils.h
		metautils_bits.h
		metautils_macros.h

		rrd.c rrd.h
		volume_lock.c volume_lock.h
		lb.c lb.h
		common_main.c common_main.h
		utils_syscall.c metautils_syscall.h
		lrutree.c lrutree.h tree.h
		storage_policy.c storage_policy.h
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
		utils_gba.c
		utils_kv.c
		utils_acl.c
		utils_l4v.c
		utils_m1url.c
		utils_meta0_info.c
		utils_metadata.c
		utils_namespace_info.c
		utils_service_info.c

		gridd_client.c gridd_client.h
		gridd_client_ext.c gridd_client_ext.h

		${CMAKE_CURRENT_BINARY_DIR}/common_variables.c
		${CMAKE_CURRENT_BINARY_DIR}/common_variables.h

		${CMAKE_CURRENT_BINARY_DIR}/constraints.c
		${CMAKE_CURRENT_BINARY_DIR}/constraints.h
		${CMAKE_CURRENT_BINARY_DIR}/constr_SET_OF.c
		${CMAKE_CURRENT_BINARY_DIR}/constr_SET_OF.h
		${CMAKE_CURRENT_BINARY_DIR}/constr_SEQUENCE_OF.c
		${CMAKE_CURRENT_BINARY_DIR}/constr_SEQUENCE_OF.h
		${CMAKE_CURRENT_BINARY_DIR}/constr_SEQUENCE.c
		${CMAKE_CURRENT_BINARY_DIR}/constr_SEQUENCE.h
		${CMAKE_CURRENT_BINARY_DIR}/constr_TYPE.c
		${CMAKE_CURRENT_BINARY_DIR}/constr_TYPE.h
		${CMAKE_CURRENT_BINARY_DIR}/constr_CHOICE.c
		${CMAKE_CURRENT_BINARY_DIR}/constr_CHOICE.h

		${CMAKE_CURRENT_BINARY_DIR}/ber_tlv_tag.c
		${CMAKE_CURRENT_BINARY_DIR}/ber_tlv_tag.h
		${CMAKE_CURRENT_BINARY_DIR}/ber_tlv_length.c
		${CMAKE_CURRENT_BINARY_DIR}/ber_tlv_length.h
		${CMAKE_CURRENT_BINARY_DIR}/der_encoder.c
		${CMAKE_CURRENT_BINARY_DIR}/der_encoder.h
		${CMAKE_CURRENT_BINARY_DIR}/ber_decoder.c
		${CMAKE_CURRENT_BINARY_DIR}/ber_decoder.h
		${CMAKE_CURRENT_BINARY_DIR}/xer_support.c
		${CMAKE_CURRENT_BINARY_DIR}/xer_support.h
		${CMAKE_CURRENT_BINARY_DIR}/xer_decoder.c
		${CMAKE_CURRENT_BINARY_DIR}/xer_decoder.h
		${CMAKE_CURRENT_BINARY_DIR}/per_opentype.c
		${CMAKE_CURRENT_BINARY_DIR}/per_support.c
		${CMAKE_CURRENT_BINARY_DIR}/per_support.h
		${CMAKE_CURRENT_BINARY_DIR}/per_encoder.c
		${CMAKE_CURRENT_BINARY_DIR}/per_encoder.h

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
		${CMAKE_CURRENT_BINARY_DIR}/ENUMERATED.c
		${CMAKE_CURRENT_BINARY_DIR}/ENUMERATED.h
		${CMAKE_CURRENT_BINARY_DIR}/REAL.c
		${CMAKE_CURRENT_BINARY_DIR}/REAL.h
		${CMAKE_CURRENT_BINARY_DIR}/NULL.c
		${CMAKE_CURRENT_BINARY_DIR}/NULL.h

		${CMAKE_CURRENT_BINARY_DIR}/asn_SEQUENCE_OF.c
		${CMAKE_CURRENT_BINARY_DIR}/asn_SEQUENCE_OF.h
		${CMAKE_CURRENT_BINARY_DIR}/asn_SET_OF.c
		${CMAKE_CURRENT_BINARY_DIR}/asn_SET_OF.h
		${CMAKE_CURRENT_BINARY_DIR}/asn_codecs.h
		${CMAKE_CURRENT_BINARY_DIR}/asn_codecs_prim.c
		${CMAKE_CURRENT_BINARY_DIR}/asn_codecs_prim.h
		${CMAKE_CURRENT_BINARY_DIR}/asn_internal.h
		${CMAKE_CURRENT_BINARY_DIR}/asn_application.h
		${CMAKE_CURRENT_BINARY_DIR}/asn_system.h

		${CMAKE_CURRENT_BINARY_DIR}/AddrInfo.c
		${CMAKE_CURRENT_BINARY_DIR}/AddrInfo.h
		${CMAKE_CURRENT_BINARY_DIR}/Message.c
		${CMAKE_CURRENT_BINARY_DIR}/Message.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta0Info.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta0Info.h
		${CMAKE_CURRENT_BINARY_DIR}/Meta0InfoSequence.c
		${CMAKE_CURRENT_BINARY_DIR}/Meta0InfoSequence.h
		${CMAKE_CURRENT_BINARY_DIR}/NamespaceInfo.c
		${CMAKE_CURRENT_BINARY_DIR}/NamespaceInfo.h
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
		-lm)

add_executable(tool_sigfpe tool_sigfpe.c)
target_link_libraries(tool_sigfpe
		metautils
		${GLIB2_LIBRARIES})


install(TARGETS metautils
		LIBRARY DESTINATION ${LD_LIBDIR}
		RUNTIME DESTINATION bin
		PUBLIC_HEADER DESTINATION include)

