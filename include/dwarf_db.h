#ifndef _DWARF_DB_H_
#define _DWARF_DB_H_

#define DW_TAG(str_, tag_) [tag_] = { .str = STRINGIFY(str_), .tag = tag_ },
static struct {
    uintmax_t tag;
    char *str;
} tags[] = {
    DW_TAG(array_type,             0x01)
    DW_TAG(class_type,             0x02)
    DW_TAG(entry_point,            0x03)
    DW_TAG(enumeration_type,       0x04)
    DW_TAG(formal_parameter,       0x05)
    DW_TAG(imported_declaration,   0x08)
    DW_TAG(label,                  0x0a)
    DW_TAG(lexical_block,          0x0b)
    DW_TAG(member,                 0x0d)
    DW_TAG(pointer_type,           0x0f)
    DW_TAG(reference_type,         0x10)
    DW_TAG(compile_unit,           0x11)
    DW_TAG(string_type,            0x12)
    DW_TAG(structure_type,         0x13)
    DW_TAG(subroutine_type,        0x15)
    DW_TAG(typedef,                0x16)
    DW_TAG(union_type,             0x17)
    DW_TAG(unspecified_parameters, 0x18)
    DW_TAG(variant,                0x19)
    DW_TAG(common_block,           0x1a)
    DW_TAG(common_inclusion,       0x1b)
    DW_TAG(inheritance,            0x1c)
    DW_TAG(inlined_subroutine,     0x1d)
    DW_TAG(module,                 0x1e)
    DW_TAG(ptr_to_member_type,     0x1f)
    DW_TAG(set_type,               0x20)
    DW_TAG(subrange_type,          0x21)
    DW_TAG(with_stmt,              0x22)
    DW_TAG(access_declaration,     0x23)
    DW_TAG(base_type,              0x24)
    DW_TAG(catch_block,            0x25)
    DW_TAG(const_type,             0x26)
    DW_TAG(constant,               0x27)
    DW_TAG(enumerator,             0x28)
    DW_TAG(file_type,              0x29)
    DW_TAG(friend,                 0x2a)
    DW_TAG(namelist,               0x2b)
    DW_TAG(namelist_item,          0x2c)
    DW_TAG(packed_type,            0x2d)
    DW_TAG(subprogram,             0x2e)
    DW_TAG(template_type_param,    0x2f)
    DW_TAG(template_value_param,   0x30)
    DW_TAG(thrown_type,            0x31)
    DW_TAG(try_block,              0x32)
    DW_TAG(variant_part,           0x33)
    DW_TAG(variable,               0x34)
    DW_TAG(volatile_type,          0x35)
};
#undef DW_TAG

#define DW_AT(str_, attr_, class_) \
    {                              \
        .attr = attr_,             \
        .str = STRINGIFY(str_),    \
        .class = class_            \
    },
static struct {
    uintmax_t attr;
    char *str;
    enum dwarf_class class;
} attribs[] = {
    DW_AT(sibling,                0x01, dwarf_class_ref)
    DW_AT(location,               0x02, dwarf_class_block|dwarf_class_const)
    DW_AT(name,                   0x03, dwarf_class_str)
    DW_AT(ordering,               0x09, dwarf_class_const)
    DW_AT(byte_size,              0x0b, dwarf_class_const)
    DW_AT(bit_offset,             0x0c, dwarf_class_const)
    DW_AT(bit_size,               0x0d, dwarf_class_const)
    DW_AT(stmt_list,              0x10, dwarf_class_const)
    DW_AT(low_pc,                 0x11, dwarf_class_addr)
    DW_AT(high_pc,                0x12, dwarf_class_addr)
    DW_AT(language,               0x13, dwarf_class_const)
    DW_AT(discr,                  0x15, dwarf_class_ref)
    DW_AT(discr_value,            0x16, dwarf_class_const)
    DW_AT(visibility,             0x17, dwarf_class_const)
    DW_AT(import,                 0x18, dwarf_class_ref)
    DW_AT(string_length,          0x19, dwarf_class_block|dwarf_class_const)
    DW_AT(common_reference,       0x1a, dwarf_class_ref)
    DW_AT(comp_dir,               0x1b, dwarf_class_str)
    DW_AT(const_value,            0x1c, dwarf_class_str|dwarf_class_block|dwarf_class_const)
    DW_AT(containing_type,        0x1d, dwarf_class_ref)
    DW_AT(default_value,          0x1e, dwarf_class_ref)
    DW_AT(inline,                 0x20, dwarf_class_const)
    DW_AT(is_optional,            0x21, dwarf_class_flag)
    DW_AT(lower_bound,            0x22, dwarf_class_ref|dwarf_class_const)
    DW_AT(producer,               0x25, dwarf_class_str)
    DW_AT(prototyped,             0x27, dwarf_class_flag)
    DW_AT(return_addr,            0x2a, dwarf_class_block|dwarf_class_const)
    DW_AT(start_scope,            0x2c, dwarf_class_const)
    DW_AT(stride_size,            0x2e, dwarf_class_const)
    DW_AT(upper_bound,            0x2f, dwarf_class_ref|dwarf_class_const)
    DW_AT(abstract_origin,        0x31, dwarf_class_ref)
    DW_AT(accessibility,          0x32, dwarf_class_const)
    DW_AT(address_class,          0x33, dwarf_class_const)
    DW_AT(artificial,             0x34, dwarf_class_flag)
    DW_AT(base_types,             0x35, dwarf_class_ref)
    DW_AT(calling_convention,     0x36, dwarf_class_const)
    DW_AT(count,                  0x37, dwarf_class_ref|dwarf_class_const)
    DW_AT(data_member_location,   0x38, dwarf_class_block|dwarf_class_ref)
    DW_AT(decl_column,            0x39, dwarf_class_const)
    DW_AT(decl_file,              0x3a, dwarf_class_const)
    DW_AT(decl_line,              0x3b, dwarf_class_const)
    DW_AT(declaration,            0x3c, dwarf_class_flag)
    DW_AT(discr_list,             0x3d, dwarf_class_block)
    DW_AT(encoding,               0x3e, dwarf_class_const)
    DW_AT(external,               0x3f, dwarf_class_flag)
    DW_AT(frame_base,             0x40, dwarf_class_block|dwarf_class_const)
    DW_AT(friend,                 0x41, dwarf_class_ref)
    DW_AT(identifier_case,        0x42, dwarf_class_const)
    DW_AT(macro_info,             0x43, dwarf_class_const)
    DW_AT(namelist_item,          0x44, dwarf_class_block)
    DW_AT(priority,               0x45, dwarf_class_ref)
    DW_AT(segment,                0x46, dwarf_class_block|dwarf_class_const)
    DW_AT(specification,          0x47, dwarf_class_ref)
    DW_AT(static_link,            0x48, dwarf_class_block|dwarf_class_const)
    DW_AT(type,                   0x49, dwarf_class_ref)
    DW_AT(use_location,           0x4a, dwarf_class_block|dwarf_class_const)
    DW_AT(variable_parameter,     0x4b, dwarf_class_flag)
    DW_AT(virtuality,             0x4c, dwarf_class_const)
    DW_AT(vtable_elem_location,   0x4d, dwarf_class_block|dwarf_class_ref)
    DW_AT(allocated,              0x4e, dwarf_class_block|dwarf_class_const|dwarf_class_ref)
    DW_AT(associated,             0x4f, dwarf_class_block|dwarf_class_const|dwarf_class_ref)
    DW_AT(data_location,          0x50, dwarf_class_block)
    DW_AT(byte_stride,            0x51, dwarf_class_block|dwarf_class_const|dwarf_class_ref)
    DW_AT(entry_pc,               0x52, dwarf_class_addr)
    DW_AT(use_UTF8,               0x53, dwarf_class_flag)
    DW_AT(extension,              0x54, dwarf_class_ref)
    DW_AT(ranges,                 0x55, 0) /* rangelistptr */
    DW_AT(trampoline,             0x56, dwarf_class_addr|dwarf_class_flag|dwarf_class_ref|dwarf_class_str)
    DW_AT(call_column,            0x57, dwarf_class_const)
    DW_AT(call_file,              0x58, dwarf_class_const)
    DW_AT(call_line,              0x59, dwarf_class_const)
    DW_AT(description,            0x5a, dwarf_class_str)
    DW_AT(binary_scale,           0x5b, dwarf_class_const)
    DW_AT(decimal_scale,          0x5c, dwarf_class_const)
    DW_AT(small,                  0x5d, dwarf_class_ref)
    DW_AT(decimal_sign,           0x5e, dwarf_class_const)
    DW_AT(digit_count,            0x5f, dwarf_class_const)
    DW_AT(picture_string,         0x60, dwarf_class_str)
    DW_AT(mutable,                0x61, dwarf_class_flag)
    DW_AT(threads_scaled,         0x62, dwarf_class_flag)
    DW_AT(explicit,               0x63, dwarf_class_flag)
    DW_AT(object_pointer,         0x64, dwarf_class_ref)
    DW_AT(endianity,              0x65, dwarf_class_const)
    DW_AT(elemental,              0x66, dwarf_class_flag)
    DW_AT(pure,                   0x67, dwarf_class_flag)
    DW_AT(recursive,              0x68, dwarf_class_flag)
};
#undef DW_AT

enum DW_AT {
    DW_AT_sibling              = 0x01,
    DW_AT_location             = 0x02,
    DW_AT_name                 = 0x03,
    DW_AT_ordering             = 0x09,
    DW_AT_byte_size            = 0x0b,
    DW_AT_bit_offset           = 0x0c,
    DW_AT_bit_size             = 0x0d,
    DW_AT_stmt_list            = 0x10,
    DW_AT_low_pc               = 0x11,
    DW_AT_high_pc              = 0x12,
    DW_AT_language             = 0x13,
    DW_AT_discr                = 0x15,
    DW_AT_discr_value          = 0x16,
    DW_AT_visibility           = 0x17,
    DW_AT_import               = 0x18,
    DW_AT_string_length        = 0x19,
    DW_AT_common_reference     = 0x1a,
    DW_AT_comp_dir             = 0x1b,
    DW_AT_const_value          = 0x1c,
    DW_AT_containing_type      = 0x1d,
    DW_AT_default_value        = 0x1e,
    DW_AT_inline               = 0x20,
    DW_AT_is_optional          = 0x21,
    DW_AT_lower_bound          = 0x22,
    DW_AT_producer             = 0x25,
    DW_AT_prototyped           = 0x27,
    DW_AT_return_addr          = 0x2a,
    DW_AT_start_scope          = 0x2c,
    DW_AT_stride_size          = 0x2e,
    DW_AT_upper_bound          = 0x2f,
    DW_AT_abstract_origin      = 0x31,
    DW_AT_accessibility        = 0x32,
    DW_AT_address_class        = 0x33,
    DW_AT_artificial           = 0x34,
    DW_AT_base_types           = 0x35,
    DW_AT_calling_convention   = 0x36,
    DW_AT_count                = 0x37,
    DW_AT_data_member_location = 0x38,
    DW_AT_decl_column          = 0x39,
    DW_AT_decl_file            = 0x3a,
    DW_AT_decl_line            = 0x3b,
    DW_AT_declaration          = 0x3c,
    DW_AT_discr_list           = 0x3d,
    DW_AT_encoding             = 0x3e,
    DW_AT_external             = 0x3f,
    DW_AT_frame_base           = 0x40,
    DW_AT_friend               = 0x41,
    DW_AT_identifier_case      = 0x42,
    DW_AT_macro_info           = 0x43,
    DW_AT_namelist_item        = 0x44,
    DW_AT_priority             = 0x45,
    DW_AT_segment              = 0x46,
    DW_AT_specification        = 0x47,
    DW_AT_static_link          = 0x48,
    DW_AT_type                 = 0x49,
    DW_AT_use_location         = 0x4a,
    DW_AT_variable_parameter   = 0x4b,
    DW_AT_virtuality           = 0x4c,
    DW_AT_vtable_elem_location = 0x4d,
    DW_AT_allocated            = 0x4e,
    DW_AT_associated           = 0x4f,
    DW_AT_data_location        = 0x50,
    DW_AT_byte_stride          = 0x51,
    DW_AT_entry_pc             = 0x52,
    DW_AT_use_UTF8             = 0x53,
    DW_AT_extension            = 0x54,
    DW_AT_ranges               = 0x55,
    DW_AT_trampoline           = 0x56,
    DW_AT_call_column          = 0x57,
    DW_AT_call_file            = 0x58,
    DW_AT_call_line            = 0x59,
    DW_AT_description          = 0x5a,
    DW_AT_binary_scale         = 0x5b,
    DW_AT_decimal_scale        = 0x5c,
    DW_AT_small                = 0x5d,
    DW_AT_decimal_sign         = 0x5e,
    DW_AT_digit_count          = 0x5f,
    DW_AT_picture_string       = 0x60,
    DW_AT_mutable              = 0x61,
    DW_AT_threads_scaled       = 0x62,
    DW_AT_explicit             = 0x63,
    DW_AT_object_pointer       = 0x64,
    DW_AT_endianity            = 0x65,
    DW_AT_elemental            = 0x66,
    DW_AT_pure                 = 0x67,
    DW_AT_recursive            = 0x68,
};

enum DW_TAG {
    DW_TAG_array_type             = 0x01,
    DW_TAG_class_type             = 0x02,
    DW_TAG_entry_point            = 0x03,
    DW_TAG_enumeration_type       = 0x04,
    DW_TAG_formal_parameter       = 0x05,
    DW_TAG_imported_declaration   = 0x08,
    DW_TAG_label                  = 0x0a,
    DW_TAG_lexical_block          = 0x0b,
    DW_TAG_member                 = 0x0d,
    DW_TAG_pointer_type           = 0x0f,
    DW_TAG_reference_type         = 0x10,
    DW_TAG_compile_unit           = 0x11,
    DW_TAG_string_type            = 0x12,
    DW_TAG_structure_type         = 0x13,
    DW_TAG_subroutine_type        = 0x15,
    DW_TAG_typedef                = 0x16,
    DW_TAG_union_type             = 0x17,
    DW_TAG_unspecified_parameters = 0x18,
    DW_TAG_variant                = 0x19,
    DW_TAG_common_block           = 0x1a,
    DW_TAG_common_inclusion       = 0x1b,
    DW_TAG_inheritance            = 0x1c,
    DW_TAG_inlined_subroutine     = 0x1d,
    DW_TAG_module                 = 0x1e,
    DW_TAG_ptr_to_member_type     = 0x1f,
    DW_TAG_set_type               = 0x20,
    DW_TAG_subrange_type          = 0x21,
    DW_TAG_with_stmt              = 0x22,
    DW_TAG_access_declaration     = 0x23,
    DW_TAG_base_type              = 0x24,
    DW_TAG_catch_block            = 0x25,
    DW_TAG_const_type             = 0x26,
    DW_TAG_constant               = 0x27,
    DW_TAG_enumerator             = 0x28,
    DW_TAG_file_type              = 0x29,
    DW_TAG_friend                 = 0x2a,
    DW_TAG_namelist               = 0x2b,
    DW_TAG_namelist_item          = 0x2c,
    DW_TAG_packed_type            = 0x2d,
    DW_TAG_subprogram             = 0x2e,
    DW_TAG_template_type_param    = 0x2f,
    DW_TAG_template_value_param   = 0x30,
    DW_TAG_thrown_type            = 0x31,
    DW_TAG_try_block              = 0x32,
    DW_TAG_variant_part           = 0x33,
    DW_TAG_variable               = 0x34,
    DW_TAG_volatile_type          = 0x35,
};

#endif /* _DWARF_DB_H_ */

