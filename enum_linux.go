// +build linux

package serial

import (
	"io/ioutil"
	"regexp"
	"strings"
)

// EnumerateSerialPorts lists all serial ports.
// Based on https://github.com/bugst/go-serial
func EnumerateSerialPorts() ([]string, []string, error) {
	files, err := ioutil.ReadDir(devFolder)
	if err != nil {
		return nil, nil, err
	}

	ports := make([]string, 0, len(files))

	for _, f := range files {
		// Skip folders
		if f.IsDir() {
			continue
		}
		// Keep only devices with the correct name
		match, err := regexp.MatchString(regexFilter, f.Name())
		if err != nil {
			return nil, nil, err
		}

		if !match {
			continue
		}

		portName := devFolder + "/" + f.Name()

		if strings.HasPrefix(f.Name(), "ttyS") {
			c := &Config{Name: portName, Baud: 115200}
			s, err := OpenPort(c)

			if err != nil {
				continue
			} else {
				s.Close()
			}

		}

		// Save serial port in the resulting list
		ports = append(ports, portName)

	}

	return ports, nil, nil
}
