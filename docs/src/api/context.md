# Cancelling preparation

`NewFuzzerWithContext(ctx, projectConfig)` covers preparation: compiler discovery,
installation through solc-select, compilation and Slither. Cancellation returns an
error recognized by `errors.Is(err, context.Canceled)` or
`errors.Is(err, context.DeadlineExceeded)`. A failed version check caused by
cancellation does not start an installation. Cancelled Slither does not become a
successful AST fallback; ordinary Slither failures retain that fallback.

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
f, err := fuzzing.NewFuzzerWithContext(ctx, projectConfig)
if err != nil {
    return err
}
// The preparation context does not control this later campaign.
return f.Start()
```

`CompilationConfig`, `SolcCompilationConfig` and `CryticCompilationConfig` expose
`CompileContext(ctx)` with the same results as `Compile()`. Version discovery has
`GetSystemSolcVersionContext(ctx)`; Slither has
`RunSlitherContext(ctx, target, solcVersion)`. A cancellable custom backend must
implement `ContextPlatformConfig`; the adapter does not run an unsupported
backend in an abandoned goroutine.

The old constructors, `Compile()` and `RunSlither()` remain available and use a
noncancelable background context. This preserves foreground compiler signal
handling and the existing FFI command helper. `SOLC_VERSION` stays local to each
command. Concurrent compilations need distinct export/cache directories.

For cancellable commands, the process runner owns a Unix process group or a
Windows Job Object. Windows starts the root suspended, assigns it to the job,
then resumes it. Cleanup also handles descendants after the root exits. Output
streams remain separate; combined output is only diagnostic. Cancellation and
ordinary exit errors retain `errors.Is`/`errors.As` identity. Arbitrary Go readers
cannot be interrupted safely, so cancellable commands require nil or `*os.File`
stdin. The legacy helper keeps its existing input behavior.
Process-control and capture failures are recognized by
`errors.Is(err, utils.ErrCommandControl)` and stop preparation; they cannot trigger
Slither's AST fallback or a compiler installation.

Unix cleanup allows 250 ms for graceful termination, then forces termination;
pipe draining is bounded to one second. Deliberately escaping a Unix process
group, or crossing from WSL into Windows executables, is outside that ownership
guarantee. This is process lifecycle management, not a sandbox. Windows job
ownership uses the documented
[process creation flags](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags)
and [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

The CLI registers its signal context before constructing the fuzzer and retains
it through runtime readiness. A cancellation request is stored before checking
readiness; readiness is published before checking the stored request. Thus a
signal between construction and `Start()` cannot be lost or call uninitialized
runtime cancellation functions. The observer is joined and hooks are restored
on return. Corpus cleaning shares this preparation context and runtime bridge.
Arbitrary Go setup callbacks or external RPC operations that ignore cancellation
do not gain a new bounded-completion guarantee.
