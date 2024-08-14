// This file is generated by rust-protobuf 3.5.0. Do not edit
// .proto file is parsed by pure
// @generated

// https://github.com/rust-lang/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]

#![allow(unused_attributes)]
#![cfg_attr(rustfmt, rustfmt::skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unused_results)]
#![allow(unused_mut)]

//! Generated file from `attestation-agent.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_3_5_0;

// @@protoc_insertion_point(message:attestation_agent.ExtendRuntimeMeasurementRequest)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct ExtendRuntimeMeasurementRequest {
    // message fields
    // @@protoc_insertion_point(field:attestation_agent.ExtendRuntimeMeasurementRequest.Domain)
    pub Domain: ::std::string::String,
    // @@protoc_insertion_point(field:attestation_agent.ExtendRuntimeMeasurementRequest.Operation)
    pub Operation: ::std::string::String,
    // @@protoc_insertion_point(field:attestation_agent.ExtendRuntimeMeasurementRequest.Content)
    pub Content: ::std::string::String,
    // @@protoc_insertion_point(field:attestation_agent.ExtendRuntimeMeasurementRequest.RegisterIndex)
    pub RegisterIndex: ::std::option::Option<u64>,
    // special fields
    // @@protoc_insertion_point(special_field:attestation_agent.ExtendRuntimeMeasurementRequest.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a ExtendRuntimeMeasurementRequest {
    fn default() -> &'a ExtendRuntimeMeasurementRequest {
        <ExtendRuntimeMeasurementRequest as ::protobuf::Message>::default_instance()
    }
}

impl ExtendRuntimeMeasurementRequest {
    pub fn new() -> ExtendRuntimeMeasurementRequest {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(4);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "Domain",
            |m: &ExtendRuntimeMeasurementRequest| { &m.Domain },
            |m: &mut ExtendRuntimeMeasurementRequest| { &mut m.Domain },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "Operation",
            |m: &ExtendRuntimeMeasurementRequest| { &m.Operation },
            |m: &mut ExtendRuntimeMeasurementRequest| { &mut m.Operation },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "Content",
            |m: &ExtendRuntimeMeasurementRequest| { &m.Content },
            |m: &mut ExtendRuntimeMeasurementRequest| { &mut m.Content },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
            "RegisterIndex",
            |m: &ExtendRuntimeMeasurementRequest| { &m.RegisterIndex },
            |m: &mut ExtendRuntimeMeasurementRequest| { &mut m.RegisterIndex },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<ExtendRuntimeMeasurementRequest>(
            "ExtendRuntimeMeasurementRequest",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for ExtendRuntimeMeasurementRequest {
    const NAME: &'static str = "ExtendRuntimeMeasurementRequest";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    self.Domain = is.read_string()?;
                },
                18 => {
                    self.Operation = is.read_string()?;
                },
                26 => {
                    self.Content = is.read_string()?;
                },
                32 => {
                    self.RegisterIndex = ::std::option::Option::Some(is.read_uint64()?);
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if !self.Domain.is_empty() {
            my_size += ::protobuf::rt::string_size(1, &self.Domain);
        }
        if !self.Operation.is_empty() {
            my_size += ::protobuf::rt::string_size(2, &self.Operation);
        }
        if !self.Content.is_empty() {
            my_size += ::protobuf::rt::string_size(3, &self.Content);
        }
        if let Some(v) = self.RegisterIndex {
            my_size += ::protobuf::rt::uint64_size(4, v);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if !self.Domain.is_empty() {
            os.write_string(1, &self.Domain)?;
        }
        if !self.Operation.is_empty() {
            os.write_string(2, &self.Operation)?;
        }
        if !self.Content.is_empty() {
            os.write_string(3, &self.Content)?;
        }
        if let Some(v) = self.RegisterIndex {
            os.write_uint64(4, v)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> ExtendRuntimeMeasurementRequest {
        ExtendRuntimeMeasurementRequest::new()
    }

    fn clear(&mut self) {
        self.Domain.clear();
        self.Operation.clear();
        self.Content.clear();
        self.RegisterIndex = ::std::option::Option::None;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static ExtendRuntimeMeasurementRequest {
        static instance: ExtendRuntimeMeasurementRequest = ExtendRuntimeMeasurementRequest {
            Domain: ::std::string::String::new(),
            Operation: ::std::string::String::new(),
            Content: ::std::string::String::new(),
            RegisterIndex: ::std::option::Option::None,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for ExtendRuntimeMeasurementRequest {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("ExtendRuntimeMeasurementRequest").unwrap()).clone()
    }
}

impl ::std::fmt::Display for ExtendRuntimeMeasurementRequest {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for ExtendRuntimeMeasurementRequest {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

// @@protoc_insertion_point(message:attestation_agent.ExtendRuntimeMeasurementResponse)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct ExtendRuntimeMeasurementResponse {
    // special fields
    // @@protoc_insertion_point(special_field:attestation_agent.ExtendRuntimeMeasurementResponse.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a ExtendRuntimeMeasurementResponse {
    fn default() -> &'a ExtendRuntimeMeasurementResponse {
        <ExtendRuntimeMeasurementResponse as ::protobuf::Message>::default_instance()
    }
}

impl ExtendRuntimeMeasurementResponse {
    pub fn new() -> ExtendRuntimeMeasurementResponse {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(0);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<ExtendRuntimeMeasurementResponse>(
            "ExtendRuntimeMeasurementResponse",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for ExtendRuntimeMeasurementResponse {
    const NAME: &'static str = "ExtendRuntimeMeasurementResponse";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> ExtendRuntimeMeasurementResponse {
        ExtendRuntimeMeasurementResponse::new()
    }

    fn clear(&mut self) {
        self.special_fields.clear();
    }

    fn default_instance() -> &'static ExtendRuntimeMeasurementResponse {
        static instance: ExtendRuntimeMeasurementResponse = ExtendRuntimeMeasurementResponse {
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for ExtendRuntimeMeasurementResponse {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("ExtendRuntimeMeasurementResponse").unwrap()).clone()
    }
}

impl ::std::fmt::Display for ExtendRuntimeMeasurementResponse {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for ExtendRuntimeMeasurementResponse {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x17attestation-agent.proto\x12\x11attestation_agent\"\xae\x01\n\x1fEx\
    tendRuntimeMeasurementRequest\x12\x16\n\x06Domain\x18\x01\x20\x01(\tR\
    \x06Domain\x12\x1c\n\tOperation\x18\x02\x20\x01(\tR\tOperation\x12\x18\n\
    \x07Content\x18\x03\x20\x01(\tR\x07Content\x12)\n\rRegisterIndex\x18\x04\
    \x20\x01(\x04H\0R\rRegisterIndex\x88\x01\x01B\x10\n\x0e_RegisterIndex\"\
    \"\n\x20ExtendRuntimeMeasurementResponse2\x9f\x01\n\x17AttestationAgentS\
    ervice\x12\x83\x01\n\x18ExtendRuntimeMeasurement\x122.attestation_agent.\
    ExtendRuntimeMeasurementRequest\x1a3.attestation_agent.ExtendRuntimeMeas\
    urementResponseb\x06proto3\
";

/// `FileDescriptorProto` object which was a source for this generated file
fn file_descriptor_proto() -> &'static ::protobuf::descriptor::FileDescriptorProto {
    static file_descriptor_proto_lazy: ::protobuf::rt::Lazy<::protobuf::descriptor::FileDescriptorProto> = ::protobuf::rt::Lazy::new();
    file_descriptor_proto_lazy.get(|| {
        ::protobuf::Message::parse_from_bytes(file_descriptor_proto_data).unwrap()
    })
}

/// `FileDescriptor` object which allows dynamic access to files
pub fn file_descriptor() -> &'static ::protobuf::reflect::FileDescriptor {
    static generated_file_descriptor_lazy: ::protobuf::rt::Lazy<::protobuf::reflect::GeneratedFileDescriptor> = ::protobuf::rt::Lazy::new();
    static file_descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::FileDescriptor> = ::protobuf::rt::Lazy::new();
    file_descriptor.get(|| {
        let generated_file_descriptor = generated_file_descriptor_lazy.get(|| {
            let mut deps = ::std::vec::Vec::with_capacity(0);
            let mut messages = ::std::vec::Vec::with_capacity(2);
            messages.push(ExtendRuntimeMeasurementRequest::generated_message_descriptor_data());
            messages.push(ExtendRuntimeMeasurementResponse::generated_message_descriptor_data());
            let mut enums = ::std::vec::Vec::with_capacity(0);
            ::protobuf::reflect::GeneratedFileDescriptor::new_generated(
                file_descriptor_proto(),
                deps,
                messages,
                enums,
            )
        });
        ::protobuf::reflect::FileDescriptor::new_generated_2(generated_file_descriptor)
    })
}
