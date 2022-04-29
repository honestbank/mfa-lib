// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/honestbank/mfa-lib/challenge (interfaces: IChallenge)

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockIChallenge is a mock of IChallenge interface.
type MockIChallenge struct {
	ctrl     *gomock.Controller
	recorder *MockIChallengeMockRecorder
}

// MockIChallengeMockRecorder is the mock recorder for MockIChallenge.
type MockIChallengeMockRecorder struct {
	mock *MockIChallenge
}

// NewMockIChallenge creates a new mock instance.
func NewMockIChallenge(ctrl *gomock.Controller) *MockIChallenge {
	mock := &MockIChallenge{ctrl: ctrl}
	mock.recorder = &MockIChallengeMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockIChallenge) EXPECT() *MockIChallengeMockRecorder {
	return m.recorder
}

// GetName mocks base method.
func (m *MockIChallenge) GetName() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetName")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetName indicates an expected call of GetName.
func (mr *MockIChallengeMockRecorder) GetName() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetName", reflect.TypeOf((*MockIChallenge)(nil).GetName))
}

// Request mocks base method.
func (m *MockIChallenge) Request(arg0 context.Context, arg1 map[string]interface{}) (*map[string]interface{}, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Request", arg0, arg1)
	ret0, _ := ret[0].(*map[string]interface{})
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Request indicates an expected call of Request.
func (mr *MockIChallengeMockRecorder) Request(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Request", reflect.TypeOf((*MockIChallenge)(nil).Request), arg0, arg1)
}

// Solve mocks base method.
func (m *MockIChallenge) Solve(arg0 context.Context, arg1 map[string]interface{}) (*map[string]interface{}, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Solve", arg0, arg1)
	ret0, _ := ret[0].(*map[string]interface{})
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Solve indicates an expected call of Solve.
func (mr *MockIChallengeMockRecorder) Solve(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Solve", reflect.TypeOf((*MockIChallenge)(nil).Solve), arg0, arg1)
}