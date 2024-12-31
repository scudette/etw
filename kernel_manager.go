package etw

/*

   #include <session.h>
*/
import "C"

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	KernelInfo = NewKernelInfoManager()
)

type Process struct {
	PID int

	Mappings []*Mapping
}

func (self *Process) AddMapping(mapping *Mapping) {
	self.Mappings = append(self.Mappings, mapping)
}

func (self *Process) GetMapping(addr uint64) (*Mapping, bool) {
	for _, m := range self.Mappings {
		if m.BaseAddr < addr && addr < m.EndAddr {
			return m, true
		}
	}
	return nil, false
}

type Handle struct {
	PID uint32

	// Object is the kernel address for the relevant object
	Object, Handle, Name, Type string
}

// A global manager that maintains information about the kernel. Can
// be queried by other ETW processors.
type KernelInfoManager struct {
	mu sync.Mutex

	// Lookup the handle quickly from its kernel address.
	handleByObject map[string]*Handle

	typeNames map[string]string

	// Key = Object -> Value is full key name
	keysCache map[string]string

	processInfos map[uint64]*Process

	// A lookup from kernel device names to drive letters.
	deviceLookup map[string]string

	// A cache of known PE Symbols. Key is PE path
	peCache map[string]*PESymbols

	previousEvent *Event
}

func (self *KernelInfoManager) getType(typeId string) string {
	name, ok := self.typeNames[typeId]
	if ok {
		return name
	}

	return ""
}

func (self *KernelInfoManager) normalizeFilename(filename string) string {
	for deviceName, driveLetter := range self.deviceLookup {
		if strings.HasPrefix(filename, deviceName) {
			return driveLetter + filename[len(deviceName):]
		}
	}
	return filename
}

func (self *KernelInfoManager) decorateStackTraces(e *Event) []string {
	var tb []string

	event_props := e.Props()
	StackProcess, _ := event_props.GetString("StackProcess")
	pid, err := strconv.ParseUint(StackProcess, 0, 64)
	if err != nil {
		return nil
	}

	kernel_process, _ := self.processInfos[0]

	process, pres := self.processInfos[pid]
	if !pres {
		return nil
	}

	for _, k := range event_props.Keys() {
		if !strings.HasPrefix(k, "Stack") {
			continue
		}

		v, pres := event_props.GetString(k)
		if !pres {
			continue
		}

		addr, err := strconv.ParseUint(v, 0, 64)
		if err != nil {
			continue
		}

		event_props.Update("StackProcess", addr)

		var mapping *Mapping

		// Kernel space
		if addr > 0x800000000000 {
			if kernel_process == nil {
				continue
			}

			mapping, pres = kernel_process.GetMapping(addr)
		} else {

			// Userspace
			mapping, pres = process.GetMapping(addr)
		}

		if !pres {
			continue
		}

		// Try to find the function name closest to the address
		func_name := self.guessFunctionName(
			mapping.Filename, int64(addr-mapping.BaseAddr))

		if func_name != "" {
			tb = append(tb, fmt.Sprintf("%v@%v", func_name, mapping.dll))
		}
	}

	return tb
}

func (self *KernelInfoManager) guessFunctionName(
	pe_path string, rva int64) string {

	symbols, pres := self.peCache[pe_path]
	if !pres {
		symbols, _ = self.openPE(pe_path)
		if symbols == nil {
			return ""
		}

		self.peCache[pe_path] = symbols
	}

	return symbols.getFuncName(rva)
}

func (self *KernelInfoManager) processEvent(e *Event) (ret *Event) {

	// Hold onto the event in case the next event is a stack trace, so
	// we re-emit this event with the previous
	defer func() {
		if ret != nil {
			self.previousEvent = ret
		}
	}()

	switch e.Header.KernelLoggerType {

	case ImageRundown:
		mapping, err := self.NewMapping(e.Props())
		if err != nil {
			return e
		}

		proc, pres := self.processInfos[mapping.Pid]
		if !pres {
			proc = &Process{PID: int(mapping.Pid)}
			self.processInfos[mapping.Pid] = proc
		}

		proc.AddMapping(mapping)

	case StackWalk:
		tb := self.decorateStackTraces(e)
		if len(tb) > 0 {
			// Re-emit the previous event with the backtrace
			// decoration.
			event_props := self.previousEvent.Props()
			event_props.Set("Backtrace", tb)
			return self.previousEvent
		}
		// Suppress backtraces we can not resolve.
		return nil

	case RegKCBRundown, RegCreateKCB, RegDeleteKCB:
		event_props := e.Props()
		KeyHandle, _ := event_props.GetString("KeyHandle")
		KeyName, _ := event_props.GetString("KeyName")

		if KeyName != "" && KeyHandle != "" {
			self.keysCache[KeyHandle] = KeyName
		}

	case RegDeleteKey:
		event_props := e.Props()
		KeyHandle, _ := event_props.GetString("KeyHandle")

		if KeyHandle != "" {
			delete(self.keysCache, KeyHandle)
		}

	case RegQueryValue, RegCloseKey, RegOpenKey,
		RegCreateKey, RegSetValue, RegDeleteValue:
		event_props := e.Props()
		KeyName, _ := event_props.GetString("KeyName")
		KeyHandle, _ := event_props.GetString("KeyHandle")

		// When the key handle is 0 key name is the full key path.
		if KeyHandle == "0x0" {
			event_props.Set("RegistryPath", KeyName)
			return e
		}

		resolved, pres := self.keysCache[KeyHandle]
		if pres {
			event_props.Set("RegistryPath", Join(resolved, KeyName))
			return e
		}

		// Unfortunately there are many cases where the key handle is
		// not know.

	case CreateHandle:
		h := &Handle{PID: e.Header.ProcessID}

		event_props := e.Props()
		h.Object, _ = event_props.GetString("Object")
		h.Handle, _ = event_props.GetString("Handle")
		h.Name, _ = event_props.GetString("ObjectName")
		h.Type, _ = event_props.GetString("ObjectType")

		self.handleByObject[h.Object] = h

		type_name, pres := self.typeNames[h.Type]
		if pres {
			event_props.Set("ObjectTypeName", type_name)
		}

	case CloseHandle:
		event_props := e.Props()
		Object, _ := event_props.GetString("Object")
		Type, _ := event_props.GetString("ObjectType")

		name, pres := self.typeNames[Type]
		if pres {
			event_props.Set("ObjectTypeName", name)
		}
		delete(self.handleByObject, Object)
	}

	return e
}

func NewKernelInfoManager() *KernelInfoManager {
	res := &KernelInfoManager{
		handleByObject: make(map[string]*Handle),
		typeNames:      GetObjectTypes(),
		keysCache:      make(map[string]string),
		processInfos:   make(map[uint64]*Process),
		deviceLookup:   getDeviceLookup(),
		peCache:        make(map[string]*PESymbols),
	}

	return res
}

func Join(a, b string) string {
	a = strings.TrimSuffix(a, "\\")
	if b != "" {
		return a + "\\" + b
	}
	return a
}

func getDeviceLookup() map[string]string {
	lookup := make(map[string]string)

	systemroot := os.Getenv("SYSTEMROOT")
	if systemroot == "" {
		systemroot = "C:\\Windows"
	}
	lookup["\\SystemRoot"] = systemroot

	bitmask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil
	}

	buffer := AllocateBuff(1024)

	for i := uint32(0); i <= 26; i++ {
		if bitmask&(1<<i) > 0 {
			drive_letter := []byte{byte(i) + 'A', ':', 0}

			res := C.QueryDosDeviceA(
				C.LPCSTR(unsafe.Pointer(&drive_letter[0])),
				C.LPSTR(unsafe.Pointer(&buffer[0])), C.DWORD(len(buffer)))
			if res > 1 {
				// Drop the final 0 because we dont need it.
				lookup[string(buffer[:res-2])] = string(drive_letter[:2])
			}

		}
	}
	return lookup
}
