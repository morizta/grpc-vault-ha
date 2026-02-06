// Package codec provides optimized protobuf codec for gRPC using vtprotobuf
package codec

import (
	"fmt"

	"google.golang.org/grpc/encoding"
	"google.golang.org/protobuf/proto"
)

// Name is the name registered for the vtprotobuf codec.
const Name = "proto"

func init() {
	encoding.RegisterCodec(vtprotoCodec{})
}

// vtprotoCodec is a Codec implementation with vtprotobuf marshaling and unmarshaling.
type vtprotoCodec struct{}

// vtprotoMessage is implemented by vtprotobuf generated messages
type vtprotoMessage interface {
	MarshalVT() ([]byte, error)
	UnmarshalVT([]byte) error
}

func (vtprotoCodec) Marshal(v interface{}) ([]byte, error) {
	// Try vtprotobuf first (faster)
	if vt, ok := v.(vtprotoMessage); ok {
		return vt.MarshalVT()
	}
	// Fallback to standard protobuf
	if m, ok := v.(proto.Message); ok {
		return proto.Marshal(m)
	}
	return nil, fmt.Errorf("failed to marshal: %T is not a proto.Message", v)
}

func (vtprotoCodec) Unmarshal(data []byte, v interface{}) error {
	// Try vtprotobuf first (faster)
	if vt, ok := v.(vtprotoMessage); ok {
		return vt.UnmarshalVT(data)
	}
	// Fallback to standard protobuf
	if m, ok := v.(proto.Message); ok {
		return proto.Unmarshal(data, m)
	}
	return fmt.Errorf("failed to unmarshal: %T is not a proto.Message", v)
}

func (vtprotoCodec) Name() string {
	return Name
}
