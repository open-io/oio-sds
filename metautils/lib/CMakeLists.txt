add_definitions(-DG_LOG_DOMAIN="oio.utils")

include_directories(BEFORE . ../..
		${CMAKE_BINARY_DIR}
		${CMAKE_BINARY_DIR}/metautils/asn1c
		${CMAKE_CURRENT_BINARY_DIR})

link_directories()

include_directories(AFTER
		${JSONC_INCLUDE_DIRS})


add_custom_command(
	OUTPUT
		${CMAKE_BINARY_DIR}/metautils/asn1c/constraints.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/constraints.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/constr_SET_OF.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/constr_SET_OF.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/constr_SEQUENCE_OF.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/constr_SEQUENCE_OF.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/constr_SEQUENCE.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/constr_SEQUENCE.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/constr_TYPE.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/constr_TYPE.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/constr_CHOICE.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/constr_CHOICE.h

		${CMAKE_BINARY_DIR}/metautils/asn1c/ber_tlv_tag.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/ber_tlv_tag.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/ber_tlv_length.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/ber_tlv_length.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/der_encoder.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/der_encoder.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/ber_decoder.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/ber_decoder.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/xer_support.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/xer_support.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/xer_decoder.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/xer_decoder.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/per_support.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/per_support.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/per_encoder.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/per_encoder.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/xer_encoder.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/xer_encoder.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/per_decoder.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/per_decoder.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/per_opentype.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/per_opentype.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/converter-sample.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/NativeEnumerated.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/NativeEnumerated.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/NativeInteger.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/NativeInteger.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/OCTET_STRING.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/OCTET_STRING.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/PrintableString.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/PrintableString.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/BIT_STRING.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/BIT_STRING.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/BOOLEAN.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/BOOLEAN.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/INTEGER.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/INTEGER.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/ENUMERATED.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/ENUMERATED.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/REAL.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/REAL.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/NULL.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/NULL.h

		${CMAKE_BINARY_DIR}/metautils/asn1c/asn_SEQUENCE_OF.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/asn_SEQUENCE_OF.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/asn_SET_OF.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/asn_SET_OF.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/asn_codecs.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/asn_codecs_prim.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/asn_codecs_prim.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/asn_internal.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/asn_system.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/asn_application.h

		${CMAKE_BINARY_DIR}/metautils/asn1c/AddrInfo.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/AddrInfo.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/Message.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/Message.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/Meta0Info.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/Meta0Info.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/Meta0InfoSequence.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/Meta0InfoSequence.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/NamespaceInfo.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/NamespaceInfo.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/Parameter.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/Parameter.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/ParameterSequence.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/ParameterSequence.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/Score.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/Score.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/ServiceInfo.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/ServiceInfo.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/ServiceInfoSequence.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/ServiceInfoSequence.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/ServiceTag.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/ServiceTag.h

		${CMAKE_BINARY_DIR}/metautils/asn1c/RowFieldSequence.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/RowFieldSequence.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/RowFieldValue.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/RowFieldValue.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/RowFieldType.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/RowFieldType.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/RowField.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/RowField.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/Row.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/Row.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/RowSet.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/RowSet.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/RowName.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/RowName.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/TableHeader.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/TableHeader.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/Table.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/Table.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/TableSequence.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/TableSequence.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/TableVersion.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/TableVersion.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/BaseVersion.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/BaseVersion.h

		${CMAKE_BINARY_DIR}/metautils/asn1c/M2V2BeanSequence.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/M2V2BeanSequence.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/M2V2Bean.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/M2V2Bean.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/M2V2Alias.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/M2V2Alias.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/M2V2Chunk.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/M2V2Chunk.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/M2V2ContentHeader.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/M2V2ContentHeader.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/M2V2Property.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/M2V2Property.h

	PRE_BUILD
	COMMAND
	mkdir -p ${CMAKE_BINARY_DIR}/metautils/asn1c && cd ${CMAKE_BINARY_DIR}/metautils/asn1c && ${ASN1C_EXECUTABLE}
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

		${CMAKE_BINARY_DIR}/metautils/asn1c/constraints.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/constraints.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/constr_SET_OF.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/constr_SET_OF.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/constr_SEQUENCE_OF.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/constr_SEQUENCE_OF.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/constr_SEQUENCE.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/constr_SEQUENCE.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/constr_TYPE.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/constr_TYPE.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/constr_CHOICE.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/constr_CHOICE.h

		${CMAKE_BINARY_DIR}/metautils/asn1c/ber_tlv_tag.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/ber_tlv_tag.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/ber_tlv_length.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/ber_tlv_length.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/der_encoder.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/der_encoder.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/ber_decoder.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/ber_decoder.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/xer_support.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/xer_support.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/xer_decoder.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/xer_decoder.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/per_opentype.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/per_opentype.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/per_support.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/per_support.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/per_encoder.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/per_encoder.h

		${CMAKE_BINARY_DIR}/metautils/asn1c/NativeEnumerated.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/NativeEnumerated.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/NativeInteger.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/NativeInteger.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/OCTET_STRING.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/OCTET_STRING.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/PrintableString.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/PrintableString.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/BIT_STRING.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/BIT_STRING.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/BOOLEAN.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/BOOLEAN.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/INTEGER.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/INTEGER.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/ENUMERATED.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/ENUMERATED.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/REAL.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/REAL.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/NULL.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/NULL.h

		${CMAKE_BINARY_DIR}/metautils/asn1c/asn_SEQUENCE_OF.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/asn_SEQUENCE_OF.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/asn_SET_OF.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/asn_SET_OF.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/asn_codecs.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/asn_codecs_prim.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/asn_codecs_prim.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/asn_internal.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/asn_application.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/asn_system.h

		${CMAKE_BINARY_DIR}/metautils/asn1c/AddrInfo.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/AddrInfo.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/Message.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/Message.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/Meta0Info.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/Meta0Info.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/Meta0InfoSequence.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/Meta0InfoSequence.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/NamespaceInfo.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/NamespaceInfo.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/Parameter.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/Parameter.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/ParameterSequence.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/ParameterSequence.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/Score.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/Score.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/ServiceInfo.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/ServiceInfo.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/ServiceInfoSequence.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/ServiceInfoSequence.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/ServiceTag.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/ServiceTag.h

		${CMAKE_BINARY_DIR}/metautils/asn1c/RowFieldSequence.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/RowFieldSequence.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/RowFieldValue.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/RowFieldValue.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/RowFieldType.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/RowFieldType.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/RowField.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/RowField.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/Row.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/Row.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/RowSet.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/RowSet.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/RowName.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/RowName.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/TableHeader.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/TableHeader.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/Table.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/Table.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/TableSequence.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/TableSequence.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/TableVersion.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/TableVersion.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/BaseVersion.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/BaseVersion.h

		${CMAKE_BINARY_DIR}/metautils/asn1c/M2V2BeanSequence.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/M2V2BeanSequence.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/M2V2Bean.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/M2V2Bean.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/M2V2Alias.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/M2V2Alias.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/M2V2Chunk.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/M2V2Chunk.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/M2V2ContentHeader.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/M2V2ContentHeader.c
		${CMAKE_BINARY_DIR}/metautils/asn1c/M2V2Property.h
		${CMAKE_BINARY_DIR}/metautils/asn1c/M2V2Property.c

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

