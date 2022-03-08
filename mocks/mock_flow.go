// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/honestbank/mfa-lib/flow (interfaces: IFlow)

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	entities "github.com/honestbank/mfa-lib/jwt/entities"
	entities0 "github.com/honestbank/mfa-lib/mfa/entities"
)

// MockIFlow is a mock of IFlow interface.
type MockIFlow struct {
	ctrl     *gomock.Controller
	recorder *MockIFlowMockRecorder
}

// MockIFlowMockRecorder is the mock recorder for MockIFlow.
type MockIFlowMockRecorder struct {
	mock *MockIFlow
}

// NewMockIFlow creates a new mock instance.
func NewMockIFlow(ctrl *gomock.Controller) *MockIFlow {
	mock := &MockIFlow{ctrl: ctrl}
	mock.recorder = &MockIFlowMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockIFlow) EXPECT() *MockIFlowMockRecorder {
	return m.recorder
}

// GetChallenges mocks base method.
func (m *MockIFlow) GetChallenges() []string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetChallenges")
	ret0, _ := ret[0].([]string)
	return ret0
}

// GetChallenges indicates an expected call of GetChallenges.
func (mr *MockIFlowMockRecorder) GetChallenges() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetChallenges", reflect.TypeOf((*MockIFlow)(nil).GetChallenges))
}

// GetName mocks base method.
func (m *MockIFlow) GetName() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetName")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetName indicates an expected call of GetName.
func (mr *MockIFlowMockRecorder) GetName() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetName", reflect.TypeOf((*MockIFlow)(nil).GetName))
}

// Initialize mocks base method.
func (m *MockIFlow) Initialize(arg0 context.Context) (*entities.JWTAdditions, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Initialize", arg0)
	ret0, _ := ret[0].(*entities.JWTAdditions)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Initialize indicates an expected call of Initialize.
func (mr *MockIFlowMockRecorder) Initialize(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Initialize", reflect.TypeOf((*MockIFlow)(nil).Initialize), arg0)
}

// Request mocks base method.
func (m *MockIFlow) Request(arg0, arg1 string, arg2 entities0.JWTData) (*map[string]interface{}, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Request", arg0, arg1, arg2)
	ret0, _ := ret[0].(*map[string]interface{})
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Request indicates an expected call of Request.
func (mr *MockIFlowMockRecorder) Request(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Request", reflect.TypeOf((*MockIFlow)(nil).Request), arg0, arg1, arg2)
}

// Resolve mocks base method.
func (m *MockIFlow) Resolve(arg0 entities0.JWTData) (*map[string]interface{}, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resolve", arg0)
	ret0, _ := ret[0].(*map[string]interface{})
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Resolve indicates an expected call of Resolve.
func (mr *MockIFlowMockRecorder) Resolve(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resolve", reflect.TypeOf((*MockIFlow)(nil).Resolve), arg0)
}

// Solve mocks base method.
func (m *MockIFlow) Solve(arg0, arg1 string, arg2 entities0.JWTData) (*map[string]interface{}, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Solve", arg0, arg1, arg2)
	ret0, _ := ret[0].(*map[string]interface{})
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Solve indicates an expected call of Solve.
func (mr *MockIFlowMockRecorder) Solve(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Solve", reflect.TypeOf((*MockIFlow)(nil).Solve), arg0, arg1, arg2)
}

// Validate mocks base method.
func (m *MockIFlow) Validate(arg0 context.Context, arg1 string, arg2 entities0.JWTData) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Validate", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// Validate indicates an expected call of Validate.
func (mr *MockIFlowMockRecorder) Validate(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Validate", reflect.TypeOf((*MockIFlow)(nil).Validate), arg0, arg1, arg2)
}
