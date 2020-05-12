// OpenIO SDS Go rawx
// Copyright (C) 2018-2020 OpenIO SAS
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
	"net"
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

type beanstalkClient struct {
	cnx       net.Conn
	addr      string
	bufReader *bufio.Reader
}

func DialBeanstalkd(addr string) (*beanstalkClient, error) {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return nil, err
	}

	bc := new(beanstalkClient)
	bc.cnx = conn
	bc.addr = addr
	bc.bufReader = bufio.NewReader(conn)
	return bc, nil
}

func (bc *beanstalkClient) Close() {
	_, _ = bc.sendAll([]byte("quit \r\n"))
	if bc.cnx != nil {
		err := bc.cnx.Close()
		if err != nil {
			LogWarning("Failed to close the cnx to beanstalkClient: %s", err.Error())
		}
	}
}

func (bc *beanstalkClient) Use(tubename string) error {
	cmd := bytes.Buffer{}
	cmd.Grow(256)
	cmd.WriteString("use ")
	cmd.WriteString(tubename)
	cmd.WriteString("\r\n")
	expected := fmt.Sprintf("USING %s\r\n", tubename)
	return bc.sendCommandAndCheck(cmd.Bytes(), expected)
}

func (bc *beanstalkClient) Put(data []byte) (uint64, error) {
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
	resp, err := bc.sendCommand(cmd.Bytes())
	if err != nil {
		return 0, err
	}

	if len(resp) <= 0 {
		return 0, parseBeanstalkError(resp)
	}

	var id uint64
	switch resp[0] {
	case 'I':
		_, err := fmt.Sscanf(resp, "INSERTED %d\r\n", &id)
		return id, err
	case 'B':
		_, _ = fmt.Sscanf(resp, "BURIED %d\r\n", &id)
		return id, errBuried
	default:
		return 0, parseBeanstalkError(resp)
	}
}

func (bc *beanstalkClient) sendCommandAndCheck(command []byte, expected string) error {
	resp, err := bc.sendCommand(command)
	if err != nil {
		return err
	}

	if resp != expected {
		return parseBeanstalkError(resp)
	}
	return nil
}

func (bc *beanstalkClient) sendCommand(command []byte) (string, error) {
	_, err := bc.sendAll(command)
	if err != nil {
		return "", err
	}

	resp, err := bc.bufReader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return resp, nil
}

func (bc *beanstalkClient) sendAll(data []byte) (int, error) {
	if bc.cnx == nil {
		return 0, errors.New("No connection to beanstalkClient")
	}

	lengthData := len(data)
	toWrite := data
	totalWritten := 0
	var n int
	var err error
	for totalWritten < lengthData {
		n, err = bc.cnx.Write(toWrite)
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

func parseBeanstalkError(str string) error {
	if err, ok := errorTable[str]; ok {
		return err
	}
	return fmt.Errorf("unknown error: %v", str)
}
