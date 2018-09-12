// OpenIO SDS Go rawx
// Copyright (C) 2018 OpenIO SAS
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
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
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

const (
	defaultPriority uint64 = 1 << 31
	defaultTTR      uint64 = 120
)

var (
	ErrOutOfMemory    = errors.New("out of memory")
	ErrInternalError  = errors.New("internal error")
	ErrBadFormat      = errors.New("bad format")
	ErrUnknownCommand = errors.New("unknown command")
	ErrBuried         = errors.New("buried")
	ErrExpectedCrlf   = errors.New("expected CRLF")
	ErrJobTooBig      = errors.New("job too big")
	ErrDraining       = errors.New("draining")
	ErrDeadlineSoon   = errors.New("deadline soon")
	ErrTimedOut       = errors.New("timed out")
	ErrNotFound       = errors.New("not found")
)

var errorTable = map[string]error{
	"DEADLINE_SOON\r\n": ErrDeadlineSoon,
	"TIMED_OUT\r\n":     ErrTimedOut,
	"EXPECTED_CRLF\r\n": ErrExpectedCrlf,
	"JOB_TOO_BIG\r\n":   ErrJobTooBig,
	"DRAINING\r\n":      ErrDraining,
	"BURIED\r\n":        ErrBuried,
	"NOT_FOUND\r\n":     ErrNotFound,

	// common error
	"OUT_OF_MEMORY\r\n":   ErrOutOfMemory,
	"INTERNAL_ERROR\r\n":  ErrInternalError,
	"BAD_FORMAT\r\n":      ErrBadFormat,
	"UNKNOWN_COMMAND\r\n": ErrUnknownCommand,
}

type Beanstalkd struct {
	conn      net.Conn
	addr      string
	bufReader *bufio.Reader
}

type Job struct {
	ID   uint64
	Data []byte
}

func DialBeanstalkd(addr string) (*Beanstalkd, error) {
	conn, err := net.Dial("tcp", addr)
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
	beanstalkd.sendAll([]byte("quit \r\n"))
	beanstalkd.conn.Close()
}

func (beanstalkd *Beanstalkd) Watch(tubename string) error {
	command := fmt.Sprintf("watch %s\r\n", tubename)
	resp, err := beanstalkd.sendCommand(command)
	if err != nil {
		return err
	}

	var tubeCount int
	_, err = fmt.Sscanf(resp, "WATCHING %d\r\n", &tubeCount)
	if err != nil {
		return beanstalkd.parseError(resp)
	}
	return nil
}

func (beanstalkd *Beanstalkd) Use(tubename string) error {
	command := fmt.Sprintf("use %s\r\n", tubename)
	expected := fmt.Sprintf("USING %s\r\n", tubename)
	return beanstalkd.sendCommandAndCheck(command, expected)
}

func (beanstalkd *Beanstalkd) Put(data []byte) (uint64, error) {
	command := fmt.Sprintf("put %d %d %d %d\r\n%s\r\n", defaultPriority,
		0, defaultTTR, len(data), string(data))
	resp, err := beanstalkd.sendCommand(command)
	if err != nil {
		return 0, err
	}

	switch {
	case strings.HasPrefix(resp, "INSERTED"):
		var id uint64
		_, err := fmt.Sscanf(resp, "INSERTED %d\r\n", &id)
		return id, err
	case strings.HasPrefix(resp, "BURIED"):
		var id uint64
		fmt.Sscanf(resp, "BURIED %d\r\n", &id)
		return id, ErrBuried
	default:
		return 0, beanstalkd.parseError(resp)
	}
}

func (beanstalkd *Beanstalkd) Reserve() (*Job, error) {
	command := "reserve\r\n"
	resp, err := beanstalkd.sendCommand(command)
	if err != nil {
		return nil, err
	}

	switch {
	case strings.HasPrefix(resp, "RESERVED"):
		job := new(Job)
		var dataLen int
		_, err = fmt.Sscanf(resp, "RESERVED %d %d\r\n", &(job.ID), &dataLen)
		if err != nil {
			return nil, err
		}
		job.Data, err = beanstalkd.readData(dataLen)
		return job, err
	default:
		return nil, beanstalkd.parseError(resp)
	}
}

func (beanstalkd *Beanstalkd) Bury(id uint64) error {
	command := fmt.Sprintf("bury %d %d\r\n", id, defaultPriority)
	expected := "BURIED\r\n"
	return beanstalkd.sendCommandAndCheck(command, expected)
}

func (beanstalkd *Beanstalkd) Release(id uint64) error {
	command := fmt.Sprintf("release %d %d %d\r\n", id, defaultPriority, 0)
	expected := "RELEASED\r\n"
	return beanstalkd.sendCommandAndCheck(command, expected)
}

func (beanstalkd *Beanstalkd) Delete(id uint64) error {
	command := fmt.Sprintf("delete %d\r\n", id)
	expected := "DELETED\r\n"
	return beanstalkd.sendCommandAndCheck(command, expected)
}

func (beanstalkd *Beanstalkd) KickJob(id uint64) error {
	command := fmt.Sprintf("kick-job %d\r\n", id)
	expected := "KICKED\r\n"
	return beanstalkd.sendCommandAndCheck(command, expected)
}

func (beanstalkd *Beanstalkd) Kick(bound uint64) (uint64, error) {
	command := fmt.Sprintf("kick %d\r\n", bound)
	resp, err := beanstalkd.sendCommand(command)
	if err != nil {
		return 0, err
	}

	switch {
	case strings.HasPrefix(resp, "KICKED"):
		var kicked uint64
		fmt.Sscanf(resp, "KICKED %d\r\n", &kicked)
		return kicked, nil
	default:
		return 0, beanstalkd.parseError(resp)
	}
}

func (beanstalkd *Beanstalkd) sendCommandAndCheck(command, expected string) error {
	resp, err := beanstalkd.sendCommand(command)
	if err != nil {
		return err
	}

	if resp != expected {
		return beanstalkd.parseError(resp)
	}
	return nil
}

func (beanstalkd *Beanstalkd) sendCommand(command string) (string, error) {
	_, err := beanstalkd.sendAll([]byte(command))
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

func (beanstalkd *Beanstalkd) parseError(str string) error {
	if err, ok := errorTable[str]; ok {
		return err
	}
	return fmt.Errorf("unknown error: %v", str)
}
