// OpenIO SDS Go rawx
// Copyright (C) 2015-2020 OpenIO SAS
// Copyright (C) 2021-2024 OVH SAS
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Affero General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with this program. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"io/ioutil"
	"os"
	"os/user"

	"gopkg.in/ini.v1"
	"openio-sds/rawx/defs"
	"openio-sds/rawx/logger"
)

var OioConfig map[string]map[string]string

var optsParser = ini.LoadOptions{
	AllowPythonMultilineValues: true,
	SpaceBeforeInlineComment:   true,
}

func oioLoadFile(file string) {
	cfg, err := ini.LoadSources(optsParser, file)
	if err != nil {
		logger.LogWarning("Failed to load config file [%s]: %s", file, err)
		return
	}

	sections := cfg.Sections()
	for _, section := range sections {
		namespace := section.Name()
		if _, ok := OioConfig[namespace]; !ok {
			OioConfig[namespace] = make(map[string]string)
		}
		for k, v := range section.KeysHash() {
			OioConfig[namespace][k] = v
		}
	}
}

func oioLoadDir(directory string) {
	files, err := ioutil.ReadDir(directory)
	if err != nil {
		logger.LogWarning("Failed to load config directory [%s]: %s", directory, err)
		return
	}

	for _, fi := range files {
		if fi.Mode().IsRegular() {
			oioLoadFile(directory + "/" + fi.Name())
		}
	}
}

func oioLoadConfig() {
	if fi, err := os.Stat(defs.PathOioConfigFile); err == nil && fi.Mode().IsRegular() {
		oioLoadFile(defs.PathOioConfigFile)
	}

	if fi, err := os.Stat(defs.PathOioConfigDir); err == nil && fi.IsDir() {
		oioLoadDir(defs.PathOioConfigDir)
	}

	if usr, err := user.Current(); err == nil {
		local := usr.HomeDir + "/" + defs.PathOioConfigLocal
		if fi, err := os.Stat(local); err == nil && fi.Mode().IsRegular() {
			oioLoadFile(local)
		}

		// Yes, it happens...
		if home := os.Getenv("HOME"); home != usr.HomeDir {
			local = home + "/" + defs.PathOioConfigLocal
			if fi, err := os.Stat(local); err == nil && fi.Mode().IsRegular() {
				oioLoadFile(local)
			}
		}
	}

	if len(OioConfig) == 0 {
		logger.LogWarning("No namespace configuration file found in %s or %s "+
			"or user home directory", defs.PathOioConfigFile, defs.PathOioConfigDir)
	}
}

func oioGetConfigValue(namespace, value string) string {
	if len(OioConfig) == 0 {
		OioConfig = make(map[string]map[string]string)
		oioLoadConfig()
	}

	if namespace == "" {
		namespace = "default"
	}

	confVal, ok := OioConfig[namespace][value]
	if ok {
		return confVal
	}
	return ""
}

func OioGetEventAgent(namespace string) string {
	conf := oioGetConfigValue(namespace, defs.ConfigOioEventAgentRawx)
	if conf == "" {
		conf = oioGetConfigValue(namespace, defs.ConfigOioEventAgent)
	}
	return conf
}
