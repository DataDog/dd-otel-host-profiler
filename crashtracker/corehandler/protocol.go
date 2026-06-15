package corehandler

// Protocol defines message types for the unix socket protocol
// between the core pattern handler and the daemon.

// MessageType identifies the type of message sent over the socket.
type MessageType uint8

const (
	MsgCrashStart  MessageType = 1
	MsgProcMaps    MessageType = 2
	MsgProcStatus  MessageType = 3
	MsgProcEnviron MessageType = 4
	MsgRegisters   MessageType = 5
	MsgThreads     MessageType = 6
	MsgDone        MessageType = 7
	MsgAck         MessageType = 8
)

// CrashStartMsg is the initial message from the handler to the daemon.
type CrashStartMsg struct {
	PID     uint32
	Signal  uint32
	ExeName string
}
