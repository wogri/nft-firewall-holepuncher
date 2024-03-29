// Whitelist IPs proto

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.6.1
// source: whitelist.proto

package whitelist

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type WhitelistRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Attempt int64 `protobuf:"varint,1,opt,name=attempt,proto3" json:"attempt,omitempty"`
}

func (x *WhitelistRequest) Reset() {
	*x = WhitelistRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_whitelist_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *WhitelistRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WhitelistRequest) ProtoMessage() {}

func (x *WhitelistRequest) ProtoReflect() protoreflect.Message {
	mi := &file_whitelist_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WhitelistRequest.ProtoReflect.Descriptor instead.
func (*WhitelistRequest) Descriptor() ([]byte, []int) {
	return file_whitelist_proto_rawDescGZIP(), []int{0}
}

func (x *WhitelistRequest) GetAttempt() int64 {
	if x != nil {
		return x.Attempt
	}
	return 0
}

type WhitelistReply struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Whitelist []*WhitelistEntry `protobuf:"bytes,1,rep,name=whitelist,proto3" json:"whitelist,omitempty"`
}

func (x *WhitelistReply) Reset() {
	*x = WhitelistReply{}
	if protoimpl.UnsafeEnabled {
		mi := &file_whitelist_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *WhitelistReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WhitelistReply) ProtoMessage() {}

func (x *WhitelistReply) ProtoReflect() protoreflect.Message {
	mi := &file_whitelist_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WhitelistReply.ProtoReflect.Descriptor instead.
func (*WhitelistReply) Descriptor() ([]byte, []int) {
	return file_whitelist_proto_rawDescGZIP(), []int{1}
}

func (x *WhitelistReply) GetWhitelist() []*WhitelistEntry {
	if x != nil {
		return x.Whitelist
	}
	return nil
}

type WhitelistEntry struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ipv4Address string `protobuf:"bytes,1,opt,name=ipv4_address,json=ipv4Address,proto3" json:"ipv4_address,omitempty"`
	Ipv6Address string `protobuf:"bytes,2,opt,name=ipv6_address,json=ipv6Address,proto3" json:"ipv6_address,omitempty"`
	ValidUntil  int64  `protobuf:"varint,3,opt,name=valid_until,json=validUntil,proto3" json:"valid_until,omitempty"`
}

func (x *WhitelistEntry) Reset() {
	*x = WhitelistEntry{}
	if protoimpl.UnsafeEnabled {
		mi := &file_whitelist_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *WhitelistEntry) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WhitelistEntry) ProtoMessage() {}

func (x *WhitelistEntry) ProtoReflect() protoreflect.Message {
	mi := &file_whitelist_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WhitelistEntry.ProtoReflect.Descriptor instead.
func (*WhitelistEntry) Descriptor() ([]byte, []int) {
	return file_whitelist_proto_rawDescGZIP(), []int{2}
}

func (x *WhitelistEntry) GetIpv4Address() string {
	if x != nil {
		return x.Ipv4Address
	}
	return ""
}

func (x *WhitelistEntry) GetIpv6Address() string {
	if x != nil {
		return x.Ipv6Address
	}
	return ""
}

func (x *WhitelistEntry) GetValidUntil() int64 {
	if x != nil {
		return x.ValidUntil
	}
	return 0
}

var File_whitelist_proto protoreflect.FileDescriptor

var file_whitelist_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x77, 0x68, 0x69, 0x74, 0x65, 0x6c, 0x69, 0x73, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x09, 0x77, 0x68, 0x69, 0x74, 0x65, 0x6c, 0x69, 0x73, 0x74, 0x22, 0x2c, 0x0a, 0x10,
	0x57, 0x68, 0x69, 0x74, 0x65, 0x6c, 0x69, 0x73, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x18, 0x0a, 0x07, 0x61, 0x74, 0x74, 0x65, 0x6d, 0x70, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x03, 0x52, 0x07, 0x61, 0x74, 0x74, 0x65, 0x6d, 0x70, 0x74, 0x22, 0x49, 0x0a, 0x0e, 0x57, 0x68,
	0x69, 0x74, 0x65, 0x6c, 0x69, 0x73, 0x74, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x12, 0x37, 0x0a, 0x09,
	0x77, 0x68, 0x69, 0x74, 0x65, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x19, 0x2e, 0x77, 0x68, 0x69, 0x74, 0x65, 0x6c, 0x69, 0x73, 0x74, 0x2e, 0x57, 0x68, 0x69, 0x74,
	0x65, 0x6c, 0x69, 0x73, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x09, 0x77, 0x68, 0x69, 0x74,
	0x65, 0x6c, 0x69, 0x73, 0x74, 0x22, 0x77, 0x0a, 0x0e, 0x57, 0x68, 0x69, 0x74, 0x65, 0x6c, 0x69,
	0x73, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x21, 0x0a, 0x0c, 0x69, 0x70, 0x76, 0x34, 0x5f,
	0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x69,
	0x70, 0x76, 0x34, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x21, 0x0a, 0x0c, 0x69, 0x70,
	0x76, 0x36, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0b, 0x69, 0x70, 0x76, 0x36, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x1f, 0x0a,
	0x0b, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x5f, 0x75, 0x6e, 0x74, 0x69, 0x6c, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x03, 0x52, 0x0a, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x55, 0x6e, 0x74, 0x69, 0x6c, 0x32, 0x55,
	0x0a, 0x09, 0x57, 0x68, 0x69, 0x74, 0x65, 0x6c, 0x69, 0x73, 0x74, 0x12, 0x48, 0x0a, 0x08, 0x54,
	0x72, 0x61, 0x6e, 0x73, 0x66, 0x65, 0x72, 0x12, 0x1b, 0x2e, 0x77, 0x68, 0x69, 0x74, 0x65, 0x6c,
	0x69, 0x73, 0x74, 0x2e, 0x57, 0x68, 0x69, 0x74, 0x65, 0x6c, 0x69, 0x73, 0x74, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x19, 0x2e, 0x77, 0x68, 0x69, 0x74, 0x65, 0x6c, 0x69, 0x73, 0x74,
	0x2e, 0x57, 0x68, 0x69, 0x74, 0x65, 0x6c, 0x69, 0x73, 0x74, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x22,
	0x00, 0x28, 0x01, 0x30, 0x01, 0x42, 0x2b, 0x5a, 0x29, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x77, 0x6f, 0x67, 0x72, 0x69, 0x2f, 0x63, 0x61, 0x70, 0x74, 0x69, 0x76,
	0x65, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x61, 0x6c, 0x2f, 0x77, 0x68, 0x69, 0x74, 0x65, 0x6c, 0x69,
	0x73, 0x74, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_whitelist_proto_rawDescOnce sync.Once
	file_whitelist_proto_rawDescData = file_whitelist_proto_rawDesc
)

func file_whitelist_proto_rawDescGZIP() []byte {
	file_whitelist_proto_rawDescOnce.Do(func() {
		file_whitelist_proto_rawDescData = protoimpl.X.CompressGZIP(file_whitelist_proto_rawDescData)
	})
	return file_whitelist_proto_rawDescData
}

var file_whitelist_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_whitelist_proto_goTypes = []interface{}{
	(*WhitelistRequest)(nil), // 0: whitelist.WhitelistRequest
	(*WhitelistReply)(nil),   // 1: whitelist.WhitelistReply
	(*WhitelistEntry)(nil),   // 2: whitelist.WhitelistEntry
}
var file_whitelist_proto_depIdxs = []int32{
	2, // 0: whitelist.WhitelistReply.whitelist:type_name -> whitelist.WhitelistEntry
	0, // 1: whitelist.Whitelist.Transfer:input_type -> whitelist.WhitelistRequest
	1, // 2: whitelist.Whitelist.Transfer:output_type -> whitelist.WhitelistReply
	2, // [2:3] is the sub-list for method output_type
	1, // [1:2] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_whitelist_proto_init() }
func file_whitelist_proto_init() {
	if File_whitelist_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_whitelist_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*WhitelistRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_whitelist_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*WhitelistReply); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_whitelist_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*WhitelistEntry); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_whitelist_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_whitelist_proto_goTypes,
		DependencyIndexes: file_whitelist_proto_depIdxs,
		MessageInfos:      file_whitelist_proto_msgTypes,
	}.Build()
	File_whitelist_proto = out.File
	file_whitelist_proto_rawDesc = nil
	file_whitelist_proto_goTypes = nil
	file_whitelist_proto_depIdxs = nil
}
