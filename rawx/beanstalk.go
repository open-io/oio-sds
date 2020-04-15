// OpenIO SDS Go rawx
// Copyright (C) 2018-2019 OpenIO SAS
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Affero General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with this program. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPriority uint64 = 1 << 31
	defaultTTR      uint64 = 120
)

var (
	errOutOfMemory    = errors.New("out of memory")
	errInternalError  = errors.New("internal error")
	errBadFormat      = errors.New("bad format")
	errUnknownCommand = errors.New("unknown command")
	errBuried         = errors.New("buried")
	errExpectedCrlf   = errors.New("expected CRLF")
	errJobTooBig      = errors.New("job too big")
	errDraining       = errors.New("draining")
	errDeadlineSoon   = errors.New("deadline soon")
	errTimedOut       = errors.New("timed out")
	errNotFound       = errors.New("not found")
)

var errorTable = map[string]error{
	"DEADLINE_SOON\r\n": errDeadlineSoon,
	"TIMED_OUT\r\n":     errTimedOut,
	"EXPECTED_CRLF\r\n": errExpectedCrlf,
	"JOB_TOO_BIG\r\n":   errJobTooBig,
	"DRAINING\r\n":      errDraining,
	"BURIED\r\n":        errBuried,
	"NOT_FOUND\r\n":     errNotFound,

	// common error
	"OUT_OF_MEMORY\r\n":   errOutOfMemory,
	"INTERNAL_ERROR\r\n":  errInternalError,
	"BAD_FORMAT\r\n":      errBadFormat,
	"UNKNOWN_COMMAND\r\n": errUnknownCommand,
}

type Beanstalkd struct {
	conn      net.Conn
	addr      string
	bufReader *bufio.Reader
}

func itoa(i int) string    { return strconv.Itoa(i) }
func utoa(i uint64) string { return strconv.FormatUint(i, 10) }

func DialBeanstalkd(addr string) (*Beanstalkd, error) {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return nil, err
	}

	beanstalkd := new(Beanstalkd)
	beanstalkd.conn = conn
	beanstalkd.addr = addr
	beanstalkd.bufReader = bufio.NewReader(conn)
	return beanstalkd, nil
}

func (beanstalkd *Beanstalkd) Close() {
	_, _ = beanstalkd.sendAll([]byte("quit \r\n"))
	if beanstalkd.conn != nil {
		err := beanstalkd.conn.Close()
		if err != nil {
			LogWarning("Failed to close the cnx to beanstalkd: %s", err.Error())
		}
	}
}

func (beanstalkd *Beanstalkd) Use(tubename string) error {
	cmd := bytes.Buffer{}
	cmd.Grow(len(tubename) + 16)
	cmd.WriteString("use ")
	cmd.WriteString(tubename)
	cmd.WriteString("\r\n")
	expected := fmt.Sprintf("USING %s\r\n", tubename)
	return beanstalkd.sendCommandAndCheck(cmd.Bytes(), expected)
}

func (beanstalkd *Beanstalkd) Put(data []byte) (uint64, error) {
	cmd := bytes.Buffer{}
	cmd.Grow(len(data) + 64)
	cmd.WriteString("put ")
	cmd.WriteString(utoa(defaultPriority))
	cmd.WriteString(" 0 ")
	cmd.WriteString(utoa(defaultTTR))
	cmd.WriteRune(' ')
	cmd.WriteString(itoa(len(data)))
	cmd.WriteString("\r\n")
	cmd.Write(data)
	cmd.WriteString("\r\n")
	resp, err := beanstalkd.sendCommand(cmd.Bytes())
	if err != nil {
		return 0, err
	}

	switch {
	case strings.HasPrefix(resp, "IN"):
		var id uint64
		_, err := fmt.Sscanf(resp, "INSERTED %d\r\n", &id)
		return id, err
	case strings.HasPrefix(resp, "BU"):
		var id uint64
		_, _ = fmt.Sscanf(resp, "BURIED %d\r\n", &id)
		return id, errBuried
	default:
		return 0, parseBeanstalkError(resp)
	}
}

func (beanstalkd *Beanstalkd) sendCommandAndCheck(command []byte, expected string) error {
	resp, err := beanstalkd.sendCommand(command)
	if err != nil {
		return err
	}

	if resp != expected {
		return parseBeanstalkError(resp)
	}
	return nil
}

func (beanstalkd *Beanstalkd) sendCommand(command []byte) (string, error) {
	_, err := beanstalkd.sendAll(command)
	if err != nil {
		return "", err
	}

	resp, err := beanstalkd.bufReader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return resp, nil
}

func (beanstalkd *Beanstalkd) sendAll(data []byte) (int, error) {
	if beanstalkd.conn == nil {
		return 0, errors.New("No connection to beanstalkd")
	}

	lengthData := len(data)
	toWrite := data
	totalWritten := 0
	var n int
	var err error
	for totalWritten < lengthData {
		n, err = beanstalkd.conn.Write(toWrite)
		if err != nil {
			if nerr, ok := err.(net.Error); !ok || !nerr.Temporary() {
				return totalWritten, err
			}
		}
		totalWritten += n
		toWrite = toWrite[n:]
	}
	return totalWritten, nil
}

func (beanstalkd *Beanstalkd) readData(dataLen int) ([]byte, error) {
	data := make([]byte, dataLen+2) //+2 is for trailing \r\n
	n, err := io.ReadFull(beanstalkd.bufReader, data)
	if err != nil {
		return nil, err
	}

	return data[:n-2], nil //strip \r\n trail
}

func parseBeanstalkError(str string) error {
	if err, ok := errorTable[str]; ok {
		return err
	}
	return fmt.Errorf("unknown error: %v", str)
}
