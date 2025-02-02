// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/0xRafal/ibm-cloud-hyperprotectcrypto/golang/grpc (interfaces: CryptoClient)

// Package mock_grpc is a generated GoMock package.
package mock_grpc

import (
	context "context"
	gomock "github.com/golang/mock/gomock"
	grpc "github.com/0xRafal/ibm-cloud-hyperprotectcrypto/golang/grpc"
	grpc0 "google.golang.org/grpc"
	reflect "reflect"
)

// MockCryptoClient is a mock of CryptoClient interface
type MockCryptoClient struct {
	ctrl     *gomock.Controller
	recorder *MockCryptoClientMockRecorder
}

// MockCryptoClientMockRecorder is the mock recorder for MockCryptoClient
type MockCryptoClientMockRecorder struct {
	mock *MockCryptoClient
}

// NewMockCryptoClient creates a new mock instance
func NewMockCryptoClient(ctrl *gomock.Controller) *MockCryptoClient {
	mock := &MockCryptoClient{ctrl: ctrl}
	mock.recorder = &MockCryptoClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockCryptoClient) EXPECT() *MockCryptoClientMockRecorder {
	return m.recorder
}

// Decrypt mocks base method
func (m *MockCryptoClient) Decrypt(arg0 context.Context, arg1 *grpc.DecryptRequest, arg2 ...grpc0.CallOption) (*grpc.DecryptResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Decrypt", varargs...)
	ret0, _ := ret[0].(*grpc.DecryptResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Decrypt indicates an expected call of Decrypt
func (mr *MockCryptoClientMockRecorder) Decrypt(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Decrypt", reflect.TypeOf((*MockCryptoClient)(nil).Decrypt), varargs...)
}

// DecryptFinal mocks base method
func (m *MockCryptoClient) DecryptFinal(arg0 context.Context, arg1 *grpc.DecryptFinalRequest, arg2 ...grpc0.CallOption) (*grpc.DecryptFinalResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DecryptFinal", varargs...)
	ret0, _ := ret[0].(*grpc.DecryptFinalResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DecryptFinal indicates an expected call of DecryptFinal
func (mr *MockCryptoClientMockRecorder) DecryptFinal(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DecryptFinal", reflect.TypeOf((*MockCryptoClient)(nil).DecryptFinal), varargs...)
}

// DecryptInit mocks base method
func (m *MockCryptoClient) DecryptInit(arg0 context.Context, arg1 *grpc.DecryptInitRequest, arg2 ...grpc0.CallOption) (*grpc.DecryptInitResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DecryptInit", varargs...)
	ret0, _ := ret[0].(*grpc.DecryptInitResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DecryptInit indicates an expected call of DecryptInit
func (mr *MockCryptoClientMockRecorder) DecryptInit(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DecryptInit", reflect.TypeOf((*MockCryptoClient)(nil).DecryptInit), varargs...)
}

// DecryptSingle mocks base method
func (m *MockCryptoClient) DecryptSingle(arg0 context.Context, arg1 *grpc.DecryptSingleRequest, arg2 ...grpc0.CallOption) (*grpc.DecryptSingleResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DecryptSingle", varargs...)
	ret0, _ := ret[0].(*grpc.DecryptSingleResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DecryptSingle indicates an expected call of DecryptSingle
func (mr *MockCryptoClientMockRecorder) DecryptSingle(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DecryptSingle", reflect.TypeOf((*MockCryptoClient)(nil).DecryptSingle), varargs...)
}

// DecryptUpdate mocks base method
func (m *MockCryptoClient) DecryptUpdate(arg0 context.Context, arg1 *grpc.DecryptUpdateRequest, arg2 ...grpc0.CallOption) (*grpc.DecryptUpdateResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DecryptUpdate", varargs...)
	ret0, _ := ret[0].(*grpc.DecryptUpdateResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DecryptUpdate indicates an expected call of DecryptUpdate
func (mr *MockCryptoClientMockRecorder) DecryptUpdate(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DecryptUpdate", reflect.TypeOf((*MockCryptoClient)(nil).DecryptUpdate), varargs...)
}

// DeriveKey mocks base method
func (m *MockCryptoClient) DeriveKey(arg0 context.Context, arg1 *grpc.DeriveKeyRequest, arg2 ...grpc0.CallOption) (*grpc.DeriveKeyResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DeriveKey", varargs...)
	ret0, _ := ret[0].(*grpc.DeriveKeyResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeriveKey indicates an expected call of DeriveKey
func (mr *MockCryptoClientMockRecorder) DeriveKey(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeriveKey", reflect.TypeOf((*MockCryptoClient)(nil).DeriveKey), varargs...)
}

// Digest mocks base method
func (m *MockCryptoClient) Digest(arg0 context.Context, arg1 *grpc.DigestRequest, arg2 ...grpc0.CallOption) (*grpc.DigestResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Digest", varargs...)
	ret0, _ := ret[0].(*grpc.DigestResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Digest indicates an expected call of Digest
func (mr *MockCryptoClientMockRecorder) Digest(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Digest", reflect.TypeOf((*MockCryptoClient)(nil).Digest), varargs...)
}

// DigestFinal mocks base method
func (m *MockCryptoClient) DigestFinal(arg0 context.Context, arg1 *grpc.DigestFinalRequest, arg2 ...grpc0.CallOption) (*grpc.DigestFinalResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DigestFinal", varargs...)
	ret0, _ := ret[0].(*grpc.DigestFinalResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DigestFinal indicates an expected call of DigestFinal
func (mr *MockCryptoClientMockRecorder) DigestFinal(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DigestFinal", reflect.TypeOf((*MockCryptoClient)(nil).DigestFinal), varargs...)
}

// DigestInit mocks base method
func (m *MockCryptoClient) DigestInit(arg0 context.Context, arg1 *grpc.DigestInitRequest, arg2 ...grpc0.CallOption) (*grpc.DigestInitResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DigestInit", varargs...)
	ret0, _ := ret[0].(*grpc.DigestInitResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DigestInit indicates an expected call of DigestInit
func (mr *MockCryptoClientMockRecorder) DigestInit(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DigestInit", reflect.TypeOf((*MockCryptoClient)(nil).DigestInit), varargs...)
}

// DigestKey mocks base method
func (m *MockCryptoClient) DigestKey(arg0 context.Context, arg1 *grpc.DigestKeyRequest, arg2 ...grpc0.CallOption) (*grpc.DigestKeyResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DigestKey", varargs...)
	ret0, _ := ret[0].(*grpc.DigestKeyResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DigestKey indicates an expected call of DigestKey
func (mr *MockCryptoClientMockRecorder) DigestKey(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DigestKey", reflect.TypeOf((*MockCryptoClient)(nil).DigestKey), varargs...)
}

// DigestSingle mocks base method
func (m *MockCryptoClient) DigestSingle(arg0 context.Context, arg1 *grpc.DigestSingleRequest, arg2 ...grpc0.CallOption) (*grpc.DigestSingleResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DigestSingle", varargs...)
	ret0, _ := ret[0].(*grpc.DigestSingleResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DigestSingle indicates an expected call of DigestSingle
func (mr *MockCryptoClientMockRecorder) DigestSingle(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DigestSingle", reflect.TypeOf((*MockCryptoClient)(nil).DigestSingle), varargs...)
}

// DigestUpdate mocks base method
func (m *MockCryptoClient) DigestUpdate(arg0 context.Context, arg1 *grpc.DigestUpdateRequest, arg2 ...grpc0.CallOption) (*grpc.DigestUpdateResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DigestUpdate", varargs...)
	ret0, _ := ret[0].(*grpc.DigestUpdateResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DigestUpdate indicates an expected call of DigestUpdate
func (mr *MockCryptoClientMockRecorder) DigestUpdate(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DigestUpdate", reflect.TypeOf((*MockCryptoClient)(nil).DigestUpdate), varargs...)
}

// Encrypt mocks base method
func (m *MockCryptoClient) Encrypt(arg0 context.Context, arg1 *grpc.EncryptRequest, arg2 ...grpc0.CallOption) (*grpc.EncryptResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Encrypt", varargs...)
	ret0, _ := ret[0].(*grpc.EncryptResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Encrypt indicates an expected call of Encrypt
func (mr *MockCryptoClientMockRecorder) Encrypt(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Encrypt", reflect.TypeOf((*MockCryptoClient)(nil).Encrypt), varargs...)
}

// EncryptFinal mocks base method
func (m *MockCryptoClient) EncryptFinal(arg0 context.Context, arg1 *grpc.EncryptFinalRequest, arg2 ...grpc0.CallOption) (*grpc.EncryptFinalResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "EncryptFinal", varargs...)
	ret0, _ := ret[0].(*grpc.EncryptFinalResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// EncryptFinal indicates an expected call of EncryptFinal
func (mr *MockCryptoClientMockRecorder) EncryptFinal(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EncryptFinal", reflect.TypeOf((*MockCryptoClient)(nil).EncryptFinal), varargs...)
}

// EncryptInit mocks base method
func (m *MockCryptoClient) EncryptInit(arg0 context.Context, arg1 *grpc.EncryptInitRequest, arg2 ...grpc0.CallOption) (*grpc.EncryptInitResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "EncryptInit", varargs...)
	ret0, _ := ret[0].(*grpc.EncryptInitResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// EncryptInit indicates an expected call of EncryptInit
func (mr *MockCryptoClientMockRecorder) EncryptInit(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EncryptInit", reflect.TypeOf((*MockCryptoClient)(nil).EncryptInit), varargs...)
}

// EncryptSingle mocks base method
func (m *MockCryptoClient) EncryptSingle(arg0 context.Context, arg1 *grpc.EncryptSingleRequest, arg2 ...grpc0.CallOption) (*grpc.EncryptSingleResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "EncryptSingle", varargs...)
	ret0, _ := ret[0].(*grpc.EncryptSingleResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// EncryptSingle indicates an expected call of EncryptSingle
func (mr *MockCryptoClientMockRecorder) EncryptSingle(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EncryptSingle", reflect.TypeOf((*MockCryptoClient)(nil).EncryptSingle), varargs...)
}

// EncryptUpdate mocks base method
func (m *MockCryptoClient) EncryptUpdate(arg0 context.Context, arg1 *grpc.EncryptUpdateRequest, arg2 ...grpc0.CallOption) (*grpc.EncryptUpdateResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "EncryptUpdate", varargs...)
	ret0, _ := ret[0].(*grpc.EncryptUpdateResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// EncryptUpdate indicates an expected call of EncryptUpdate
func (mr *MockCryptoClientMockRecorder) EncryptUpdate(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EncryptUpdate", reflect.TypeOf((*MockCryptoClient)(nil).EncryptUpdate), varargs...)
}

// GenerateKey mocks base method
func (m *MockCryptoClient) GenerateKey(arg0 context.Context, arg1 *grpc.GenerateKeyRequest, arg2 ...grpc0.CallOption) (*grpc.GenerateKeyResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GenerateKey", varargs...)
	ret0, _ := ret[0].(*grpc.GenerateKeyResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GenerateKey indicates an expected call of GenerateKey
func (mr *MockCryptoClientMockRecorder) GenerateKey(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GenerateKey", reflect.TypeOf((*MockCryptoClient)(nil).GenerateKey), varargs...)
}

// GenerateKeyPair mocks base method
func (m *MockCryptoClient) GenerateKeyPair(arg0 context.Context, arg1 *grpc.GenerateKeyPairRequest, arg2 ...grpc0.CallOption) (*grpc.GenerateKeyPairResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GenerateKeyPair", varargs...)
	ret0, _ := ret[0].(*grpc.GenerateKeyPairResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GenerateKeyPair indicates an expected call of GenerateKeyPair
func (mr *MockCryptoClientMockRecorder) GenerateKeyPair(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GenerateKeyPair", reflect.TypeOf((*MockCryptoClient)(nil).GenerateKeyPair), varargs...)
}

// GenerateRandom mocks base method
func (m *MockCryptoClient) GenerateRandom(arg0 context.Context, arg1 *grpc.GenerateRandomRequest, arg2 ...grpc0.CallOption) (*grpc.GenerateRandomResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GenerateRandom", varargs...)
	ret0, _ := ret[0].(*grpc.GenerateRandomResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GenerateRandom indicates an expected call of GenerateRandom
func (mr *MockCryptoClientMockRecorder) GenerateRandom(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GenerateRandom", reflect.TypeOf((*MockCryptoClient)(nil).GenerateRandom), varargs...)
}

// GetAttributeValue mocks base method
func (m *MockCryptoClient) GetAttributeValue(arg0 context.Context, arg1 *grpc.GetAttributeValueRequest, arg2 ...grpc0.CallOption) (*grpc.GetAttributeValueResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetAttributeValue", varargs...)
	ret0, _ := ret[0].(*grpc.GetAttributeValueResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAttributeValue indicates an expected call of GetAttributeValue
func (mr *MockCryptoClientMockRecorder) GetAttributeValue(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAttributeValue", reflect.TypeOf((*MockCryptoClient)(nil).GetAttributeValue), varargs...)
}

// GetMechanismInfo mocks base method
func (m *MockCryptoClient) GetMechanismInfo(arg0 context.Context, arg1 *grpc.GetMechanismInfoRequest, arg2 ...grpc0.CallOption) (*grpc.GetMechanismInfoResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetMechanismInfo", varargs...)
	ret0, _ := ret[0].(*grpc.GetMechanismInfoResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetMechanismInfo indicates an expected call of GetMechanismInfo
func (mr *MockCryptoClientMockRecorder) GetMechanismInfo(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMechanismInfo", reflect.TypeOf((*MockCryptoClient)(nil).GetMechanismInfo), varargs...)
}

// GetMechanismList mocks base method
func (m *MockCryptoClient) GetMechanismList(arg0 context.Context, arg1 *grpc.GetMechanismListRequest, arg2 ...grpc0.CallOption) (*grpc.GetMechanismListResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetMechanismList", varargs...)
	ret0, _ := ret[0].(*grpc.GetMechanismListResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetMechanismList indicates an expected call of GetMechanismList
func (mr *MockCryptoClientMockRecorder) GetMechanismList(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMechanismList", reflect.TypeOf((*MockCryptoClient)(nil).GetMechanismList), varargs...)
}

// SetAttributeValue mocks base method
func (m *MockCryptoClient) SetAttributeValue(arg0 context.Context, arg1 *grpc.SetAttributeValueRequest, arg2 ...grpc0.CallOption) (*grpc.SetAttributeValueResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "SetAttributeValue", varargs...)
	ret0, _ := ret[0].(*grpc.SetAttributeValueResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SetAttributeValue indicates an expected call of SetAttributeValue
func (mr *MockCryptoClientMockRecorder) SetAttributeValue(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetAttributeValue", reflect.TypeOf((*MockCryptoClient)(nil).SetAttributeValue), varargs...)
}

// Sign mocks base method
func (m *MockCryptoClient) Sign(arg0 context.Context, arg1 *grpc.SignRequest, arg2 ...grpc0.CallOption) (*grpc.SignResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Sign", varargs...)
	ret0, _ := ret[0].(*grpc.SignResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Sign indicates an expected call of Sign
func (mr *MockCryptoClientMockRecorder) Sign(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Sign", reflect.TypeOf((*MockCryptoClient)(nil).Sign), varargs...)
}

// SignFinal mocks base method
func (m *MockCryptoClient) SignFinal(arg0 context.Context, arg1 *grpc.SignFinalRequest, arg2 ...grpc0.CallOption) (*grpc.SignFinalResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "SignFinal", varargs...)
	ret0, _ := ret[0].(*grpc.SignFinalResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SignFinal indicates an expected call of SignFinal
func (mr *MockCryptoClientMockRecorder) SignFinal(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SignFinal", reflect.TypeOf((*MockCryptoClient)(nil).SignFinal), varargs...)
}

// SignInit mocks base method
func (m *MockCryptoClient) SignInit(arg0 context.Context, arg1 *grpc.SignInitRequest, arg2 ...grpc0.CallOption) (*grpc.SignInitResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "SignInit", varargs...)
	ret0, _ := ret[0].(*grpc.SignInitResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SignInit indicates an expected call of SignInit
func (mr *MockCryptoClientMockRecorder) SignInit(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SignInit", reflect.TypeOf((*MockCryptoClient)(nil).SignInit), varargs...)
}

// SignSingle mocks base method
func (m *MockCryptoClient) SignSingle(arg0 context.Context, arg1 *grpc.SignSingleRequest, arg2 ...grpc0.CallOption) (*grpc.SignSingleResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "SignSingle", varargs...)
	ret0, _ := ret[0].(*grpc.SignSingleResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SignSingle indicates an expected call of SignSingle
func (mr *MockCryptoClientMockRecorder) SignSingle(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SignSingle", reflect.TypeOf((*MockCryptoClient)(nil).SignSingle), varargs...)
}

// SignUpdate mocks base method
func (m *MockCryptoClient) SignUpdate(arg0 context.Context, arg1 *grpc.SignUpdateRequest, arg2 ...grpc0.CallOption) (*grpc.SignUpdateResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "SignUpdate", varargs...)
	ret0, _ := ret[0].(*grpc.SignUpdateResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SignUpdate indicates an expected call of SignUpdate
func (mr *MockCryptoClientMockRecorder) SignUpdate(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SignUpdate", reflect.TypeOf((*MockCryptoClient)(nil).SignUpdate), varargs...)
}

// UnwrapKey mocks base method
func (m *MockCryptoClient) UnwrapKey(arg0 context.Context, arg1 *grpc.UnwrapKeyRequest, arg2 ...grpc0.CallOption) (*grpc.UnwrapKeyResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "UnwrapKey", varargs...)
	ret0, _ := ret[0].(*grpc.UnwrapKeyResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UnwrapKey indicates an expected call of UnwrapKey
func (mr *MockCryptoClientMockRecorder) UnwrapKey(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnwrapKey", reflect.TypeOf((*MockCryptoClient)(nil).UnwrapKey), varargs...)
}

// Verify mocks base method
func (m *MockCryptoClient) Verify(arg0 context.Context, arg1 *grpc.VerifyRequest, arg2 ...grpc0.CallOption) (*grpc.VerifyResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Verify", varargs...)
	ret0, _ := ret[0].(*grpc.VerifyResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Verify indicates an expected call of Verify
func (mr *MockCryptoClientMockRecorder) Verify(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Verify", reflect.TypeOf((*MockCryptoClient)(nil).Verify), varargs...)
}

// VerifyFinal mocks base method
func (m *MockCryptoClient) VerifyFinal(arg0 context.Context, arg1 *grpc.VerifyFinalRequest, arg2 ...grpc0.CallOption) (*grpc.VerifyFinalResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "VerifyFinal", varargs...)
	ret0, _ := ret[0].(*grpc.VerifyFinalResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifyFinal indicates an expected call of VerifyFinal
func (mr *MockCryptoClientMockRecorder) VerifyFinal(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyFinal", reflect.TypeOf((*MockCryptoClient)(nil).VerifyFinal), varargs...)
}

// VerifyInit mocks base method
func (m *MockCryptoClient) VerifyInit(arg0 context.Context, arg1 *grpc.VerifyInitRequest, arg2 ...grpc0.CallOption) (*grpc.VerifyInitResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "VerifyInit", varargs...)
	ret0, _ := ret[0].(*grpc.VerifyInitResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifyInit indicates an expected call of VerifyInit
func (mr *MockCryptoClientMockRecorder) VerifyInit(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyInit", reflect.TypeOf((*MockCryptoClient)(nil).VerifyInit), varargs...)
}

// VerifySingle mocks base method
func (m *MockCryptoClient) VerifySingle(arg0 context.Context, arg1 *grpc.VerifySingleRequest, arg2 ...grpc0.CallOption) (*grpc.VerifySingleResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "VerifySingle", varargs...)
	ret0, _ := ret[0].(*grpc.VerifySingleResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifySingle indicates an expected call of VerifySingle
func (mr *MockCryptoClientMockRecorder) VerifySingle(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifySingle", reflect.TypeOf((*MockCryptoClient)(nil).VerifySingle), varargs...)
}

// VerifyUpdate mocks base method
func (m *MockCryptoClient) VerifyUpdate(arg0 context.Context, arg1 *grpc.VerifyUpdateRequest, arg2 ...grpc0.CallOption) (*grpc.VerifyUpdateResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "VerifyUpdate", varargs...)
	ret0, _ := ret[0].(*grpc.VerifyUpdateResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifyUpdate indicates an expected call of VerifyUpdate
func (mr *MockCryptoClientMockRecorder) VerifyUpdate(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyUpdate", reflect.TypeOf((*MockCryptoClient)(nil).VerifyUpdate), varargs...)
}

// WrapKey mocks base method
func (m *MockCryptoClient) WrapKey(arg0 context.Context, arg1 *grpc.WrapKeyRequest, arg2 ...grpc0.CallOption) (*grpc.WrapKeyResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "WrapKey", varargs...)
	ret0, _ := ret[0].(*grpc.WrapKeyResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// WrapKey indicates an expected call of WrapKey
func (mr *MockCryptoClientMockRecorder) WrapKey(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WrapKey", reflect.TypeOf((*MockCryptoClient)(nil).WrapKey), varargs...)
}
