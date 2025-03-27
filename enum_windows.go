//go:build windows

package serial

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"

	"golang.org/x/sys/windows"
)

var (
	modsetupapi                           = windows.NewLazySystemDLL("setupapi.dll")
	procSetupDiGetClassDevsExW            = modsetupapi.NewProc("SetupDiGetClassDevsExW")
	procSetupDiDestroyDeviceInfoList      = modsetupapi.NewProc("SetupDiDestroyDeviceInfoList")
	procSetupDiEnumDeviceInfo             = modsetupapi.NewProc("SetupDiEnumDeviceInfo")
	procSetupDiGetDeviceRegistryPropertyW = modsetupapi.NewProc("SetupDiGetDeviceRegistryPropertyW")
)

var deviceClassPortsGUID = windows.GUID{
	Data1: 0x4d36e978,
	Data2: 0xe325,
	Data3: 0x11ce,
	Data4: [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18},
}

// DIGCF flags control what is included in the device information set built by SetupDiGetClassDevs
type DIGCF uint32

const (
	DIGCF_DEFAULT         DIGCF = 0x00000001 // only valid with DIGCF_DEVICEINTERFACE
	DIGCF_PRESENT         DIGCF = 0x00000002
	DIGCF_ALLCLASSES      DIGCF = 0x00000004
	DIGCF_PROFILE         DIGCF = 0x00000008
	DIGCF_DEVICEINTERFACE DIGCF = 0x00000010
)

type SPDRP uint32

const SPDRP_FRIENDLYNAME SPDRP = 0x0000000C // FriendlyName (R/W)

// DevInfo holds reference to device information set
type DevInfo windows.Handle

// DevInfoData is a device information structure (references a device instance that is a member of a device information set)
type DevInfoData struct {
	size      uint32
	ClassGUID windows.GUID
	DevInst   uint32 // handle
	_         uintptr
}

// Do the interface allocations only once for arg Errno values
const (
	errnoERROR_IO_PENDING = 997
)

var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
)

// errnoErr returns arg boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	return e
}

// Close function deletes a device information set and frees all associated memory.
func (h DevInfo) Close() error {
	if h != DevInfo(windows.InvalidHandle) {
		return SetupDiDestroyDeviceInfoList(h)
	}

	return nil
}

func SetupDiDestroyDeviceInfoList(DeviceInfoSet DevInfo) (err error) {
	r1, _, e1 := syscall.SyscallN(procSetupDiDestroyDeviceInfoList.Addr(), uintptr(DeviceInfoSet), 0, 0)
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

// SetupDiGetClassDevsEx function returns a handle to a device information set that contains requested device information elements for a local or a remote computer.
func SetupDiGetClassDevsEx(ClassGUID *windows.GUID, Enumerator string, hwndParent uintptr, Flags DIGCF, DeviceInfoSet DevInfo, MachineName string) (handle DevInfo, err error) {
	var _p0 *uint16
	if Enumerator != "" {
		_p0, err = syscall.UTF16PtrFromString(Enumerator)
		if err != nil {
			return
		}
	}
	var _p1 *uint16
	if MachineName != "" {
		_p1, err = syscall.UTF16PtrFromString(MachineName)
		if err != nil {
			return
		}
	}
	r0, _, e1 := syscall.SyscallN(procSetupDiGetClassDevsExW.Addr(), uintptr(unsafe.Pointer(ClassGUID)),
		uintptr(unsafe.Pointer(_p0)),
		hwndParent,
		uintptr(Flags),
		uintptr(DeviceInfoSet),
		uintptr(unsafe.Pointer(_p1)),
		uintptr(0), 0, 0)
	handle = DevInfo(r0)
	if handle == DevInfo(windows.InvalidHandle) {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

// SetupDiEnumDeviceInfo function returns an SP_DEVINFO_DATA structure that specifies a device information element in a device information set.
func SetupDiEnumDeviceInfo(DeviceInfoSet DevInfo, MemberIndex int, data *DevInfoData) (err error) {
	data.size = uint32(unsafe.Sizeof(*data))
	r1, _, e1 := syscall.SyscallN(procSetupDiEnumDeviceInfo.Addr(), uintptr(DeviceInfoSet), uintptr(MemberIndex), uintptr(unsafe.Pointer(data)))
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

// SetupDiGetDeviceRegistryProperty function retrieves a specified Plug and Play device property.
func SetupDiGetDeviceRegistryProperty(deviceInfoSet DevInfo, deviceInfoData *DevInfoData, property SPDRP) (value interface{}, err error) {
	reqSize := uint32(256)
	for {
		var dataType uint32
		buf := make([]byte, reqSize)
		r1, _, e1 := syscall.SyscallN(procSetupDiGetDeviceRegistryPropertyW.Addr(), uintptr(deviceInfoSet),
			uintptr(unsafe.Pointer(deviceInfoData)), uintptr(property), uintptr(unsafe.Pointer(&dataType)),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(uint32(len(buf))), uintptr(unsafe.Pointer(&reqSize)), 0, 0)
		if r1 == 0 {
			if e1 != 0 {
				err = errnoErr(e1)
			} else {
				err = syscall.EINVAL
			}
		}

		if err == windows.ERROR_INSUFFICIENT_BUFFER {
			continue
		}
		if err != nil {
			return
		}
		return getRegistryValue(buf[:reqSize], dataType)
	}
}

func getRegistryValue(buf []byte, dataType uint32) (interface{}, error) {
	switch dataType {
	case windows.REG_SZ:
		ret := windows.UTF16ToString(bufToUTF16(buf))
		runtime.KeepAlive(buf)
		return ret, nil
	case windows.REG_EXPAND_SZ:
		ret, err := registry.ExpandString(windows.UTF16ToString(bufToUTF16(buf)))
		runtime.KeepAlive(buf)
		return ret, err
	case windows.REG_BINARY:
		return buf, nil
	case windows.REG_DWORD_LITTLE_ENDIAN:
		return binary.LittleEndian.Uint32(buf), nil
	case windows.REG_DWORD_BIG_ENDIAN:
		return binary.BigEndian.Uint32(buf), nil
	case windows.REG_MULTI_SZ:
		bufW := bufToUTF16(buf)
		var a []string
		for i := 0; i < len(bufW); {
			j := i + wcslen(bufW[i:])
			if i < j {
				a = append(a, windows.UTF16ToString(bufW[i:j]))
			}
			i = j + 1
		}
		runtime.KeepAlive(buf)
		return a, nil
	case windows.REG_QWORD_LITTLE_ENDIAN:
		return binary.LittleEndian.Uint64(buf), nil
	default:
		return nil, fmt.Errorf("unsupported registry value type: %v", dataType)
	}
}

func wcslen(str []uint16) int {
	for i := 0; i < len(str); i++ {
		if str[i] == 0 {
			return i
		}
	}
	return len(str)
}

// bufToUTF16 function reinterprets []byte buffer as []uint16
func bufToUTF16(buf []byte) []uint16 {
	sl := struct {
		addr *uint16
		len  int
		cap  int
	}{(*uint16)(unsafe.Pointer(&buf[0])), len(buf) / 2, cap(buf) / 2}
	return *(*[]uint16)(unsafe.Pointer(&sl))
}

// EnumerateSerialPorts will return a list of port names and a list of descriptions
func EnumerateSerialPorts() ([]string, []string, error) {
	devInfoList, err := SetupDiGetClassDevsEx(&deviceClassPortsGUID, "", 0, DIGCF_PRESENT, DevInfo(0), "")
	if err != nil {
		return nil, nil, fmt.Errorf("error calling SetupDiGetClassDevsEx, %s", err.Error())
	}
	var info []string
	var ports []string
	var data DevInfoData
	for i := 0; true; i++ {
		err := SetupDiEnumDeviceInfo(devInfoList, i, &data)
		if err != nil {
			if errWin, ok := err.(syscall.Errno); ok && errWin == 259 /*ERROR_NO_MORE_ITEMS*/ {
				break
			}
			continue
		}
		value, err := SetupDiGetDeviceRegistryProperty(devInfoList, &data, SPDRP_FRIENDLYNAME)
		if err != nil {
			return ports, info, nil
		}
		if s, ok := value.(string); ok {
			if strings.Contains(s, "COM") {
				pos := strings.Index(s, "COM")
				info = append(info, s[0:pos-1])
				ports = append(ports, s[pos:len(s)-1])
			}
		}
		if data.ClassGUID != deviceClassPortsGUID {
			return nil, nil, fmt.Errorf("SetupDiEnumDeviceInfo returned different class GUID")
		}
	}
	_ = devInfoList.Close()
	return ports, info, nil
}
