package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

type cpEntry struct {
	tag  uint8
	utf8 string
}

type classReader struct {
	data []byte
	off  int
	err  error
}

func parseConstructors(data []byte) ([]string, error) {
	reader := &classReader{data: data}
	if magic := reader.u4(); magic != 0xCAFEBABE {
		return nil, fmt.Errorf("invalid Java class magic: 0x%08x", magic)
	}
	reader.u2()
	reader.u2()

	cpCount := int(reader.u2())
	if cpCount <= 0 {
		return nil, errors.New("invalid constant pool count")
	}
	cp := make([]cpEntry, cpCount)
	for i := 1; i < cpCount && reader.err == nil; i++ {
		tag := reader.u1()
		cp[i].tag = tag
		switch tag {
		case 1:
			length := int(reader.u2())
			cp[i].utf8 = string(reader.bytes(length))
		case 3, 4:
			reader.skip(4)
		case 5, 6:
			reader.skip(8)
			i++
		case 7, 8, 16, 19, 20:
			reader.skip(2)
		case 9, 10, 11, 12, 17, 18:
			reader.skip(4)
		case 15:
			reader.skip(3)
		default:
			return nil, fmt.Errorf("unsupported constant pool tag %d at index %d", tag, i)
		}
	}
	if reader.err != nil {
		return nil, reader.err
	}

	reader.skip(6)
	interfaceCount := int(reader.u2())
	reader.skip(interfaceCount * 2)

	fieldCount := int(reader.u2())
	for i := 0; i < fieldCount && reader.err == nil; i++ {
		skipMember(reader)
	}
	if reader.err != nil {
		return nil, reader.err
	}

	methodCount := int(reader.u2())
	constructors := make([]string, 0)
	for i := 0; i < methodCount && reader.err == nil; i++ {
		reader.u2()
		nameIndex := int(reader.u2())
		descriptorIndex := int(reader.u2())
		attributeCount := int(reader.u2())

		name, err := cpUtf8(cp, nameIndex)
		if err != nil {
			return nil, fmt.Errorf("invalid method name index %d: %w", nameIndex, err)
		}
		descriptor, err := cpUtf8(cp, descriptorIndex)
		if err != nil {
			return nil, fmt.Errorf("invalid method descriptor index %d: %w", descriptorIndex, err)
		}

		skipAttributes(reader, attributeCount)
		if name == "<init>" {
			constructors = append(constructors, descriptor)
		}
	}
	if reader.err != nil {
		return nil, reader.err
	}
	return constructors, nil
}

func cpUtf8(cp []cpEntry, index int) (string, error) {
	if index <= 0 || index >= len(cp) {
		return "", errors.New("index out of range")
	}
	if cp[index].tag != 1 {
		return "", fmt.Errorf("entry has tag %d, not Utf8", cp[index].tag)
	}
	return cp[index].utf8, nil
}

func skipMember(reader *classReader) {
	reader.skip(6)
	attributeCount := int(reader.u2())
	skipAttributes(reader, attributeCount)
}

func skipAttributes(reader *classReader, count int) {
	for i := 0; i < count && reader.err == nil; i++ {
		reader.u2()
		length := reader.u4()
		reader.skip(int(length))
	}
}

func allConstructorsStartWithString(constructors []string) bool {
	if len(constructors) == 0 {
		return false
	}
	for _, descriptor := range constructors {
		if !firstParameterIsJavaLangString(descriptor) {
			return false
		}
	}
	return true
}

func firstParameterIsJavaLangString(descriptor string) bool {
	const stringDescriptor = "Ljava/lang/String;"
	if len(descriptor) < 2 || descriptor[0] != '(' {
		return false
	}
	params := descriptor[1:]
	if params == "" || params[0] == ')' {
		return false
	}
	return strings.HasPrefix(params, stringDescriptor)
}

func (reader *classReader) u1() uint8 {
	if reader.err != nil {
		return 0
	}
	if reader.off+1 > len(reader.data) {
		reader.err = io.ErrUnexpectedEOF
		return 0
	}
	value := reader.data[reader.off]
	reader.off++
	return value
}

func (reader *classReader) u2() uint16 {
	if reader.err != nil {
		return 0
	}
	if reader.off+2 > len(reader.data) {
		reader.err = io.ErrUnexpectedEOF
		return 0
	}
	value := binary.BigEndian.Uint16(reader.data[reader.off:])
	reader.off += 2
	return value
}

func (reader *classReader) u4() uint32 {
	if reader.err != nil {
		return 0
	}
	if reader.off+4 > len(reader.data) {
		reader.err = io.ErrUnexpectedEOF
		return 0
	}
	value := binary.BigEndian.Uint32(reader.data[reader.off:])
	reader.off += 4
	return value
}

func (reader *classReader) bytes(length int) []byte {
	if reader.err != nil {
		return nil
	}
	if length < 0 || length > len(reader.data)-reader.off {
		reader.err = io.ErrUnexpectedEOF
		return nil
	}
	value := reader.data[reader.off : reader.off+length]
	reader.off += length
	return value
}

func (reader *classReader) skip(length int) {
	if reader.err != nil {
		return
	}
	if length < 0 || length > len(reader.data)-reader.off {
		reader.err = io.ErrUnexpectedEOF
		return
	}
	reader.off += length
}
