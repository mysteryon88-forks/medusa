package utils

import (
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Layout of JOBOBJECT_BASIC_ACCOUNTING_INFORMATION from winnt.h.
type jobAccountingInformation struct {
	TotalUserTime, TotalKernelTime                       int64
	ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime   int64
	TotalPageFaultCount, TotalProcesses, ActiveProcesses uint32
	TotalTerminatedProcesses                             uint32
}

var isProcessInJob = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")

func processInJob(process, job windows.Handle) (bool, error) {
	var member uint32
	result, _, err := isProcessInJob.Call(uintptr(process), uintptr(job), uintptr(unsafe.Pointer(&member)))
	if result == 0 {
		if err == syscall.Errno(0) {
			err = syscall.EINVAL
		}
		return false, err
	}
	return member != 0, nil
}

func startCommandTree(command *exec.Cmd) (func() error, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, commandControlError(err)
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return nil, commandControlError(errors.Join(err, windows.CloseHandle(job)))
	}
	attr := syscall.SysProcAttr{}
	if command.SysProcAttr != nil {
		attr = *command.SysProcAttr
	}
	// The primary thread cannot run user code before assignment to our job.
	attr.CreationFlags |= windows.CREATE_SUSPENDED
	attr.HideWindow = true
	command.SysProcAttr = &attr
	if err := command.Start(); err != nil {
		return nil, errors.Join(commandStartError(err), commandControlError(windows.CloseHandle(job)))
	}
	fail := func(cause error) (func() error, error) {
		killErr := command.Process.Kill()
		waitErr := command.Wait()
		return nil, commandControlError(errors.Join(cause, killErr, waitErr, windows.CloseHandle(job)))
	}
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(command.Process.Pid))
	if err != nil {
		return fail(err)
	}
	err = windows.AssignProcessToJobObject(job, process)
	_ = windows.CloseHandle(process)
	if err != nil {
		return fail(fmt.Errorf("assign suspended command to Job Object: %w", err))
	}
	if err := resumeCommandThread(uint32(command.Process.Pid)); err != nil {
		return fail(err)
	}
	return func() (cleanupErr error) {
		defer func() { cleanupErr = errors.Join(cleanupErr, windows.CloseHandle(job)) }()
		deadline := time.Now().Add(time.Second)
		// Block new child execution before taking a stable set of wait handles.
		stopLimits := limits
		stopLimits.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
		stopLimits.BasicLimitInformation.ActiveProcessLimit = 1
		_, limitErr := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&stopLimits)), uint32(unsafe.Sizeof(stopLimits)))
		handles, pinErr := pinJobProcesses(job, deadline)
		defer func() {
			for _, handle := range handles {
				cleanupErr = errors.Join(cleanupErr, windows.CloseHandle(handle))
			}
		}()
		cleanupErr = errors.Join(limitErr, pinErr, windows.TerminateJobObject(job, 1))
		for _, handle := range handles {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return errors.Join(cleanupErr, errors.New("Job Object cleanup exceeded one second"))
			}
			status, err := windows.WaitForSingleObject(handle, uint32(remaining.Milliseconds()+1))
			if err != nil || status != windows.WAIT_OBJECT_0 {
				return errors.Join(cleanupErr, err, fmt.Errorf("wait for Job Object member: status %d", status))
			}
		}
		var accounting jobAccountingInformation
		err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&accounting)), uint32(unsafe.Sizeof(accounting)), nil)
		if accounting.ActiveProcesses != 0 {
			err = errors.Join(err, errors.New("Job Object still contains active processes"))
		}
		return errors.Join(cleanupErr, err)
	}, nil
}

func pinJobProcesses(job windows.Handle, deadline time.Time) ([]windows.Handle, error) {
	var handles []windows.Handle
	for capacity := 16; capacity <= 1<<20 && time.Now().Before(deadline); capacity *= 2 {
		buffer := make([]byte, 8+capacity*int(unsafe.Sizeof(uintptr(0))))
		err := windows.QueryInformationJobObject(job, windows.JobObjectBasicProcessIdList, uintptr(unsafe.Pointer(&buffer[0])), uint32(len(buffer)), nil)
		if err == windows.ERROR_MORE_DATA {
			continue
		}
		if err != nil {
			return handles, err
		}
		count := *(*uint32)(unsafe.Pointer(&buffer[4]))
		if count > uint32(capacity) {
			return handles, errors.New("invalid Job Object process list length")
		}
		for i := uint32(0); i < count; i++ {
			if time.Now().After(deadline) {
				return handles, errors.New("Job Object enumeration exceeded cleanup budget")
			}
			pid := *(*uintptr)(unsafe.Pointer(&buffer[8+int(i)*int(unsafe.Sizeof(uintptr(0)))]))
			handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
			if err == windows.ERROR_INVALID_PARAMETER {
				continue // The process object has already been destroyed.
			}
			if err != nil {
				return handles, err
			}
			if inJob, err := processInJob(handle, job); err != nil || !inJob {
				closeErr := windows.CloseHandle(handle)
				if err != nil || closeErr != nil {
					return handles, errors.Join(err, closeErr)
				}
				continue
			}
			handles = append(handles, handle)
		}
		return handles, nil
	}
	return handles, errors.New("Job Object enumeration exceeded cleanup budget")
}

func observeCommandExit(command *exec.Cmd) commandExit {
	return commandExit{err: command.Wait(), reaped: true}
}

func resumeCommandThread(pid uint32) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	for err = windows.Thread32First(snapshot, &entry); err == nil; err = windows.Thread32Next(snapshot, &entry) {
		if entry.OwnerProcessID != pid {
			continue
		}
		thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
		if err != nil {
			return err
		}
		count, resumeErr := windows.ResumeThread(thread)
		closeErr := windows.CloseHandle(thread)
		if resumeErr != nil || closeErr != nil {
			return errors.Join(resumeErr, closeErr)
		}
		if count != 1 {
			return fmt.Errorf("unexpected primary thread suspend count %d", count)
		}
		return nil
	}
	return fmt.Errorf("find suspended command thread: %w", err)
}
