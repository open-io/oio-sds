package main

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestList_empty(t *testing.T) {
	tmpdir, err := ioutil.TempDir("/tmp", "rawx-test-")
	if err != nil {
		t.Fatal("TempDir failure: ", err)
	} else {
		defer os.RemoveAll(tmpdir)
		var rc ListSlice
		filerepo := MakeFileRepository(tmpdir)
		rc, err = filerepo.List("", "", 100)
		if err != nil {
			t.Error("List fail: ", err)
		} else if len(rc.Items) != 0 {
			t.Error("List not empty")
		}
	}
}
