/*
Package serial is a simple go package to allow you to read and write from
the serial port as a stream of bytes.

It aims to have the same API on all platforms, including windows.  As
an added bonus, the windows package does not use cgo, so you can cross
compile for windows from another platform.  Unfortunately go install
does not currently let you cross compile, so you will have to do it
manually:

	GOOS=windows make clean install

Currently, there is very little in the way of configurability.  You can
set the baud rate.  Then you can Read(), Write(), or Close() the
connection.  Read() will block until at least one byte is returned.
Write is the same.  There is currently no exposed way to set the
timeouts, though patches are welcome.

Currently, all ports are opened with 8 data bits, 1 stop bit, no
parity, no hardware flow control, and no software flow control.  This
works fine for many real devices and many faux serial devices
including usb-to-serial converters and bluetooth serial ports.

You may Read() and Write() simultaneously on the same connection (from
different goroutines).

Example usage:

	package main

	import (
	      "github.com/jkvatne/serial"
	      "log"
	)

	func main() {
	      c := &serial.Config{Name: "COM5", Baud: 115200}
	      s, err := serial.OpenPort(c)
	      if err != nil {
	              log.Fatal(err)
	      }

	      n, err := s.Write([]byte("test"))
	      if err != nil {
	              log.Fatal(err)
	      }

	      buf := make([]byte, 128)
	      n, err = s.Read(buf)
	      if err != nil {
	              log.Fatal(err)
	      }
	      log.Print("%q", buf[:n])
	}
*/
package serial

import (
	"errors"
	"time"
)

const DefaultSize = 8 // Default value for Config.Size

type StopBits byte
type Parity byte

const (
	Stop1     StopBits = 1
	Stop1Half StopBits = 15
	Stop2     StopBits = 2
)

const (
	ParityNone  Parity = 'N'
	ParityOdd   Parity = 'O'
	ParityEven  Parity = 'E'
	ParityMark  Parity = 'M' // parity bit is always 1
	ParitySpace Parity = 'S' // parity bit is always 0
)

// Config contains the information needed to open a serial port.
//
// Currently few options are implemented, but more may be added in the
// future (patches welcome), so it is recommended that you create a
// new config addressing the fields by name rather than by order.
//
// For example:
//
//	c0 := &serial.Config{Name: "COM45", Baud: 115200, ReadTimeout: time.Millisecond * 500}
//
// or
//
//	c1 := new(serial.Config)
//	c1.Name = "/dev/tty.usbserial"
//	c1.Baud = 115200
//	c1.ReadTimeout = time.Millisecond * 500
type Config struct {
	Name            string
	Baud            int
	ReadTimeout     time.Duration // Total timeout
	IntervalTimeout time.Duration // Max time between characters

	// Size is the number of data bits. If 0, DefaultSize is used.
	Size byte

	// Parity is the bit to use and defaults to ParityNone (no parity bit).
	Parity Parity

	// Number of stop bits to use. Default is 1 (1 stop bit).
	StopBits StopBits

	// RTSFlowControl bool
	// DTRFlowControl bool
	// XONFlowControl bool

	// CRLFTranslate bool
}

// ErrBadSize is returned if Size is not supported.
var ErrBadSize = errors.New("unsupported serial data size")

// ErrBadStopBits is returned if the specified StopBits setting not supported.
var ErrBadStopBits = errors.New("unsupported stop bit setting")

// ErrBadParity is returned if the parity is not supported.
var ErrBadParity = errors.New("unsupported parity setting")

// OpenPort opens a serial port with the specified configuration
func OpenPort(c *Config) (*Port, error) {
	size, par, stop := c.Size, c.Parity, c.StopBits
	if size == 0 {
		size = DefaultSize
	}
	if par == 0 {
		par = ParityNone
	}
	if stop == 0 {
		stop = Stop1
	}
	return openPort(c.Name, c.Baud, size, par, stop, c.ReadTimeout, c.IntervalTimeout)
}

// func SendBreak()

// func RegisterBreakHandler(func())
