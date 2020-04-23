// OpenIO SDS Go rawx
// Copyright (C) 2015-2020 OpenIO SAS
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
	"io/ioutil"
	"os"
	"os/user"

	"gopkg.in/ini.v1"
)

var oioConfig map[string]map[string]string

var optsParser = ini.LoadOptions{
	AllowPythonMultilineValues: true,
	SpaceBeforeInlineComment:   true,
}

func oioLoadFile(file string) {
	cfg, err := ini.LoadSources(optsParser, file)
	if err != nil {
		LogDebug("Failed to load config file [%s] : %s", file, err)
		return
	}

	sections := cfg.Sections()
	for _, section := range sections {
		namespace := section.Name()
		if _, ok := oioConfig[namespace]; !ok {
			oioConfig[namespace] = make(map[string]string)
		}
		for k, v := range section.KeysHash() {
			oioConfig[namespace][k] = v
		}
	}
}

func oioLoadDir(directory string) {
	files, err := ioutil.ReadDir(directory)
	if err != nil {
		LogDebug("Failed to load config directory [%s] : %s", directory, err)
		return
	}

	for _, fi := range files {
		if fi.Mode().IsRegular() {
			oioLoadFile(directory + "/" + fi.Name())
		}
	}
}

func oioLoadConfig() {
	if fi, err := os.Stat(oioConfigFilePath); err == nil && fi.Mode().IsRegular() {
		oioLoadFile(oioConfigFilePath)
	}

	if fi, err := os.Stat(oioConfigDirPath); err == nil && fi.IsDir() {
		oioLoadDir(oioConfigDirPath)
	}

	if usr, err := user.Current(); err == nil {
		local := usr.HomeDir + "/" + oioConfigLocalPath
		if fi, err := os.Stat(local); err == nil && fi.Mode().IsRegular() {
			oioLoadFile(local)
		}
	}
}

func oioGetConfigValue(namespace, value string) string {
	if len(oioConfig) == 0 {
		oioConfig = make(map[string]map[string]string)
		oioLoadConfig()
	}

	if namespace == "" {
		namespace = "default"
	}

	eventAgent, ok := oioConfig[namespace][value]
	if ok {
		return eventAgent
	}
	return ""
}

func OioGetEventAgent(namespace string) string {
	return oioGetConfigValue(namespace, oioConfigEventAgent)
}
