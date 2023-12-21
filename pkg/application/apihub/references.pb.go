// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v3.21.9
// source: google/cloud/apigeeregistry/v1/apihub/references.proto

// (-- api-linter: core::0215::versioned-packages=disabled
//     aip.dev/not-precedent: Support protos for the apigeeregistry.v1 API. --)

package apihub

import (
	_ "google.golang.org/genproto/googleapis/api/annotations"
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

// A ReferenceList message contains a list of references that are associated
// with a resource. A Reference is a categorized resource name or URI that
// points to some internal or external resource, respectively.
//
// ReferenceLists are used to define relationships to things like source code
// repositories, dependencies, and dependent APIs (inverse relationship of
// an API dependency).
//
// The ReferenceList is stored as an Artifact attached to a specific resource.
type ReferenceList struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Artifact identifier. May be used in YAML representations to indicate the id
	// to be used to attach the artifact.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// Artifact kind. May be used in YAML representations to identify the type of
	// this artifact.
	Kind string `protobuf:"bytes,2,opt,name=kind,proto3" json:"kind,omitempty"`
	// A human-friendly name for the reference list.
	DisplayName string `protobuf:"bytes,3,opt,name=display_name,json=displayName,proto3" json:"display_name,omitempty"`
	// A more detailed description of the reference list.
	Description string `protobuf:"bytes,4,opt,name=description,proto3" json:"description,omitempty"`
	// The list of references for the resource.
	References []*ReferenceList_Reference `protobuf:"bytes,6,rep,name=references,proto3" json:"references,omitempty"`
}

func (x *ReferenceList) Reset() {
	*x = ReferenceList{}
	if protoimpl.UnsafeEnabled {
		mi := &file_google_cloud_apigeeregistry_v1_apihub_references_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReferenceList) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReferenceList) ProtoMessage() {}

func (x *ReferenceList) ProtoReflect() protoreflect.Message {
	mi := &file_google_cloud_apigeeregistry_v1_apihub_references_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReferenceList.ProtoReflect.Descriptor instead.
func (*ReferenceList) Descriptor() ([]byte, []int) {
	return file_google_cloud_apigeeregistry_v1_apihub_references_proto_rawDescGZIP(), []int{0}
}

func (x *ReferenceList) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *ReferenceList) GetKind() string {
	if x != nil {
		return x.Kind
	}
	return ""
}

func (x *ReferenceList) GetDisplayName() string {
	if x != nil {
		return x.DisplayName
	}
	return ""
}

func (x *ReferenceList) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *ReferenceList) GetReferences() []*ReferenceList_Reference {
	if x != nil {
		return x.References
	}
	return nil
}

// Represents a single reference for a resource.
type ReferenceList_Reference struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The id of the reference.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// A human-friendly name for the reference.
	DisplayName string `protobuf:"bytes,2,opt,name=display_name,json=displayName,proto3" json:"display_name,omitempty"`
	// An optional string used to categorize the reference.
	Category string `protobuf:"bytes,3,opt,name=category,proto3" json:"category,omitempty"`
	// A resource name [AIP-122] for the item being referenced.
	// At least one of resource and uri must be set. Resource takes precedent
	// over uri in API hub.
	Resource string `protobuf:"bytes,4,opt,name=resource,proto3" json:"resource,omitempty"`
	// A URI [RFC-3986] for the item being referenced.
	// At least one of resource and uri must be set. Resource takes precedent
	// over uri in API hub.
	Uri string `protobuf:"bytes,5,opt,name=uri,proto3" json:"uri,omitempty"`
}

func (x *ReferenceList_Reference) Reset() {
	*x = ReferenceList_Reference{}
	if protoimpl.UnsafeEnabled {
		mi := &file_google_cloud_apigeeregistry_v1_apihub_references_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReferenceList_Reference) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReferenceList_Reference) ProtoMessage() {}

func (x *ReferenceList_Reference) ProtoReflect() protoreflect.Message {
	mi := &file_google_cloud_apigeeregistry_v1_apihub_references_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReferenceList_Reference.ProtoReflect.Descriptor instead.
func (*ReferenceList_Reference) Descriptor() ([]byte, []int) {
	return file_google_cloud_apigeeregistry_v1_apihub_references_proto_rawDescGZIP(), []int{0, 0}
}

func (x *ReferenceList_Reference) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *ReferenceList_Reference) GetDisplayName() string {
	if x != nil {
		return x.DisplayName
	}
	return ""
}

func (x *ReferenceList_Reference) GetCategory() string {
	if x != nil {
		return x.Category
	}
	return ""
}

func (x *ReferenceList_Reference) GetResource() string {
	if x != nil {
		return x.Resource
	}
	return ""
}

func (x *ReferenceList_Reference) GetUri() string {
	if x != nil {
		return x.Uri
	}
	return ""
}

var File_google_cloud_apigeeregistry_v1_apihub_references_proto protoreflect.FileDescriptor

var file_google_cloud_apigeeregistry_v1_apihub_references_proto_rawDesc = []byte{
	0x0a, 0x36, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2f, 0x61,
	0x70, 0x69, 0x67, 0x65, 0x65, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x79, 0x2f, 0x76, 0x31,
	0x2f, 0x61, 0x70, 0x69, 0x68, 0x75, 0x62, 0x2f, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63,
	0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x25, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e, 0x61, 0x70, 0x69, 0x67, 0x65, 0x65, 0x72, 0x65, 0x67,
	0x69, 0x73, 0x74, 0x72, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x61, 0x70, 0x69, 0x68, 0x75, 0x62, 0x1a,
	0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x66, 0x69, 0x65, 0x6c,
	0x64, 0x5f, 0x62, 0x65, 0x68, 0x61, 0x76, 0x69, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0xfc, 0x02, 0x0a, 0x0d, 0x52, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x4c, 0x69,
	0x73, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02,
	0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x12, 0x21, 0x0a, 0x0c, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61,
	0x79, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x69,
	0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65, 0x73,
	0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b,
	0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x5e, 0x0a, 0x0a, 0x72,
	0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x73, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x3e, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e, 0x61,
	0x70, 0x69, 0x67, 0x65, 0x65, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x79, 0x2e, 0x76, 0x31,
	0x2e, 0x61, 0x70, 0x69, 0x68, 0x75, 0x62, 0x2e, 0x52, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63,
	0x65, 0x4c, 0x69, 0x73, 0x74, 0x2e, 0x52, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x52,
	0x0a, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x73, 0x1a, 0xa1, 0x01, 0x0a, 0x09,
	0x52, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x12, 0x13, 0x0a, 0x02, 0x69, 0x64, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x02, 0x69, 0x64, 0x12, 0x26,
	0x0a, 0x0c, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x01, 0x52, 0x0b, 0x64, 0x69, 0x73, 0x70, 0x6c,
	0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x1f, 0x0a, 0x08, 0x63, 0x61, 0x74, 0x65, 0x67, 0x6f,
	0x72, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x01, 0x52, 0x08, 0x63,
	0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x79, 0x12, 0x1f, 0x0a, 0x08, 0x72, 0x65, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x01, 0x52, 0x08,
	0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x15, 0x0a, 0x03, 0x75, 0x72, 0x69, 0x18,
	0x05, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x01, 0x52, 0x03, 0x75, 0x72, 0x69, 0x42,
	0x78, 0x0a, 0x29, 0x63, 0x6f, 0x6d, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6c,
	0x6f, 0x75, 0x64, 0x2e, 0x61, 0x70, 0x69, 0x67, 0x65, 0x65, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74,
	0x72, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x61, 0x70, 0x69, 0x68, 0x75, 0x62, 0x42, 0x0f, 0x52, 0x65,
	0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x73, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a,
	0x38, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x61, 0x70, 0x69, 0x67,
	0x65, 0x65, 0x2f, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x79, 0x2f, 0x70, 0x6b, 0x67, 0x2f,
	0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x61, 0x70, 0x69, 0x68,
	0x75, 0x62, 0x3b, 0x61, 0x70, 0x69, 0x68, 0x75, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_google_cloud_apigeeregistry_v1_apihub_references_proto_rawDescOnce sync.Once
	file_google_cloud_apigeeregistry_v1_apihub_references_proto_rawDescData = file_google_cloud_apigeeregistry_v1_apihub_references_proto_rawDesc
)

func file_google_cloud_apigeeregistry_v1_apihub_references_proto_rawDescGZIP() []byte {
	file_google_cloud_apigeeregistry_v1_apihub_references_proto_rawDescOnce.Do(func() {
		file_google_cloud_apigeeregistry_v1_apihub_references_proto_rawDescData = protoimpl.X.CompressGZIP(file_google_cloud_apigeeregistry_v1_apihub_references_proto_rawDescData)
	})
	return file_google_cloud_apigeeregistry_v1_apihub_references_proto_rawDescData
}

var file_google_cloud_apigeeregistry_v1_apihub_references_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_google_cloud_apigeeregistry_v1_apihub_references_proto_goTypes = []interface{}{
	(*ReferenceList)(nil),           // 0: google.cloud.apigeeregistry.v1.apihub.ReferenceList
	(*ReferenceList_Reference)(nil), // 1: google.cloud.apigeeregistry.v1.apihub.ReferenceList.Reference
}
var file_google_cloud_apigeeregistry_v1_apihub_references_proto_depIdxs = []int32{
	1, // 0: google.cloud.apigeeregistry.v1.apihub.ReferenceList.references:type_name -> google.cloud.apigeeregistry.v1.apihub.ReferenceList.Reference
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_google_cloud_apigeeregistry_v1_apihub_references_proto_init() }
func file_google_cloud_apigeeregistry_v1_apihub_references_proto_init() {
	if File_google_cloud_apigeeregistry_v1_apihub_references_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_google_cloud_apigeeregistry_v1_apihub_references_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReferenceList); i {
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
		file_google_cloud_apigeeregistry_v1_apihub_references_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReferenceList_Reference); i {
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
			RawDescriptor: file_google_cloud_apigeeregistry_v1_apihub_references_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_google_cloud_apigeeregistry_v1_apihub_references_proto_goTypes,
		DependencyIndexes: file_google_cloud_apigeeregistry_v1_apihub_references_proto_depIdxs,
		MessageInfos:      file_google_cloud_apigeeregistry_v1_apihub_references_proto_msgTypes,
	}.Build()
	File_google_cloud_apigeeregistry_v1_apihub_references_proto = out.File
	file_google_cloud_apigeeregistry_v1_apihub_references_proto_rawDesc = nil
	file_google_cloud_apigeeregistry_v1_apihub_references_proto_goTypes = nil
	file_google_cloud_apigeeregistry_v1_apihub_references_proto_depIdxs = nil
}
