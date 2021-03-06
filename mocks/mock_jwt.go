// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/honestbank/mfa-lib/jwt (interfaces: IJWTService)

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	entities "github.com/honestbank/mfa-lib/mfa/entities"
)

// MockIJWTService is a mock of IJWTService interface.
type MockIJWTService struct {
	ctrl     *gomock.Controller
	recorder *MockIJWTServiceMockRecorder
}

// MockIJWTServiceMockRecorder is the mock recorder for MockIJWTService.
type MockIJWTServiceMockRecorder struct {
	mock *MockIJWTService
}

// NewMockIJWTService creates a new mock instance.
func NewMockIJWTService(ctrl *gomock.Controller) *MockIJWTService {
	mock := &MockIJWTService{ctrl: ctrl}
	mock.recorder = &MockIJWTServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockIJWTService) EXPECT() *MockIJWTServiceMockRecorder {
	return m.recorder
}

// GenerateToken mocks base method.
func (m *MockIJWTService) GenerateToken(arg0 entities.JWTData, arg1 []string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GenerateToken", arg0, arg1)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GenerateToken indicates an expected call of GenerateToken.
func (mr *MockIJWTServiceMockRecorder) GenerateToken(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GenerateToken", reflect.TypeOf((*MockIJWTService)(nil).GenerateToken), arg0, arg1)
}
