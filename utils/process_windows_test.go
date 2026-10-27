package utils

import "golang.org/x/sys/windows"

func escapeProcessFixture(string) { panic("process-group escape fixture is Unix only") }
func forkProcessFixture(string)   { panic("TERM-handler fixture is Unix only") }

func fixtureProcessGone(pid int) bool {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return err == windows.ERROR_INVALID_PARAMETER
	}
	defer windows.CloseHandle(h)
	status, err := windows.WaitForSingleObject(h, 0)
	return err == nil && status == windows.WAIT_OBJECT_0
}
