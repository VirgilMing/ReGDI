### `gdipp_server`

#### `svc_main()`
// `svc_main()` is `ServiceMain()` as in MSDN document.

<!-- > ###### Parameters

> `dwArgc` [in]

>> The number of arguments in the `lpszArgv` array.

> `lpszArgv` [in]

>> The null-terminated argument strings passed to the service by the call to the `StartService` function that started the service. If there are no arguments, this parameter can be `NULL`. Otherwise, the first argument (`lpszArgv[0]`) is the name of the service, followed by any additional arguments (`lpszArgv[1]` through `lpszArgv[dwArgc-1]`).

>> If the user starts a manual service using the Services snap-in from the Control Panel, the strings for the `lpszArgv` parameter come from the properties dialog box for the service (from the Services snap-in, right-click the service entry, click Properties, and enter the parameters in Start parameters.)

> ###### Return value

> This function does not return a value.

> ###### Remarks

> A service program can start one or more services. A service process has a `SERVICE_TABLE_ENTRY` structure for each service that it can start. The structure specifies the service name and a pointer to the `ServiceMain` function for that service.

> When the service control manager receives a request to start a service, it starts the service process (if it is not already running). The main thread of the service process calls the `StartServiceCtrlDispatcher` function with a pointer to an array of `SERVICE_TABLE_ENTRY` structures. Then the service control manager sends a start request to the service control dispatcher for this service process. The service control dispatcher creates a new thread to execute the `ServiceMain` function of the service being started.

> The `ServiceMain` function should immediately call the `RegisterServiceCtrlHandlerEx` function to specify a `HandlerEx` function to handle control requests. Next, it should call the `SetServiceStatus` function to send status information to the service control manager. After these calls, the function should complete the initialization of the service. Do not attempt to start another service in the `ServiceMain` function.

> The Service Control Manager (SCM) waits until the service reports a status of `SERVICE_RUNNING`. It is recommended that the service reports this status as quickly as possible, as other components in the system that require interaction with SCM will be blocked during this time. Some functions may require interaction with the SCM either directly or indirectly.

> The SCM locks the service control database during initialization, so if a service attempts to call `StartService` during initialization, the call will block. When the service reports to the SCM that it has successfully started, it can call `StartService`. If the service requires another service to be running, the service should set the required dependencies.

> Furthermore, you should not call any system functions during service initialization. The service code should call system functions only after it reports a status of `SERVICE_RUNNING`.

> The `ServiceMain` function should create a global event, call the `RegisterWaitForSingleObject` function on this event, and exit. This will terminate the thread that is running the `ServiceMain` function, but will not terminate the service. When the service is stopping, the service control handler should call `SetServiceStatus` with `SERVICE_STOP_PENDING` and signal this event. A thread from the thread pool will execute the wait callback function; this function should perform clean-up tasks, including closing the global event, and call `SetServiceStatus` with `SERVICE_STOPPED`. After the service has stopped, you should not execute any additional service code because you can introduce a race condition if the service receives a start control and `ServiceMain` is called again. Note that this problem is more likely to occur when multiple services share a process. -->

It calls `RegisterServiceCtrlHandlerExW()` immediately after setting 
`SERVICE_WIN32_OWN_PROCESS` and `Win32ExitCode = NO_ERROR`. W means Unicode variant.

<!-- > The `ServiceMain` function of a new service should immediately call the `RegisterServiceCtrlHandlerEx` function to register a control handler function with the control dispatcher. This enables the control dispatcher to invoke the specified function when it receives control requests for this service. For a list of possible control codes, see `HandlerEx`. The threads of the calling process can use the service status handle returned by this function to identify the service in subsequent calls to the `SetServiceStatus` function.

> The `RegisterServiceCtrlHandlerEx` function must be called before the first `SetServiceStatus` call because `RegisterServiceCtrlHandlerEx` returns a service status handle for the caller to use so that no other service can inadvertently set this service status. In addition, the control handler must be in place to receive control requests by the time the service specifies the controls it accepts through the `SetServiceStatus` function.

> When the control handler function is invoked with a control request, the service must call `SetServiceStatus` to report status to the service control manager only if the service status has changed, such as when the service is processing stop or shutdown controls. If the service status has not changed, the service should not report status to the service control manager.

> The service status handle does not have to be closed. -->

Then it calls `svc_init()`. That does not seem like an system API.

#### `svc_init()`

`h_svc_events` = `CreateEvent(NULL, TRUE, FALSE, NULL)`
if `h_svc_events` is `NULL` -> `set_svc_status(stopped, no_error, 0)`

<!-- > ##### Parameters

> `lpEventAttributes` [in, optional]

>> A pointer to a `SECURITY_ATTRIBUTES` structure. If this parameter is `NULL`, the handle cannot be inherited by child processes.

>> The `lpSecurityDescriptor` member of the structure specifies a security descriptor for the new event. If `lpEventAttributes` is `NULL`, the event gets a default security descriptor. The ACLs in the default security descriptor for an event come from the primary or impersonation token of the creator.

> `bManualReset` [in]

>> If this parameter is `TRUE`, the function creates a manual-reset event object, which requires the use of the `ResetEvent` function to set the event state to nonsignaled. If this parameter is `FALSE`, the function creates an auto-reset event object, and system automatically resets the event state to nonsignaled after a single waiting thread has been released.

> `bInitialState` [in]

>> If this parameter is `TRUE`, the initial state of the event object is signaled; otherwise, it is nonsignaled.

>`lpName` [in, optional]

>> The name of the event object. The name is limited to MAX_PATH characters. Name comparison is case sensitive.

>> If `lpName` matches the name of an existing named event object, this function requests the `EVENT_ALL_ACCESS` access right. In this case, the `bManualReset` and `bInitialState` parameters are ignored because they have already been set by the creating process. If the `lpEventAttributes` parameter is not `NULL`, it determines whether the handle can be inherited, but its security-descriptor member is ignored.

>> If `lpName` is `NULL`, the event object is created without a name.

>> If `lpName` matches the name of another kind of object in the same namespace (such as an existing semaphore, mutex, waitable timer, job, or file-mapping object), the function fails and the `GetLastError` function returns `ERROR_INVALID_HANDLE`. This occurs because these objects share the same namespace.

>> The name can have a "Global\\" or "Local\\" prefix to explicitly create the object in the global or session namespace. The remainder of the name can contain any character except the backslash character (\\). For more information, see [Kernel Object Namespaces]. Fast user switching is implemented using Terminal Services sessions. Kernel object names must follow the guidelines outlined for Terminal Services so that applications can support multiple users.

>> The object can be created in a private namespace. For more information, see [Object Namespaces].

> ##### Return value

> If the function succeeds, the return value is a handle to the event object. If the named event object existed before the function call, the function returns a handle to the existing object and `GetLastError` returns `ERROR_ALREADY_EXISTS`.

> If the function fails, the return value is `NULL`. To get extended error information, call `GetLastError`.

> ##### Remarks

> The handle returned by `CreateEvent` has the `EVENT_ALL_ACCESS` access right; it can be used in any function that requires a handle to an event object, provided that the caller has been granted access. If an event is created from a service or a thread that is impersonating a different user, you can either apply a security descriptor to the event when you create it, or change the default security descriptor for the creating process by changing its default DACL. For more information, see [Synchronization Object Security and Access Rights].

> Any thread of the calling process can specify the event-object handle in a call to one of the wait functions. The single-object wait functions return when the state of the specified object is signaled. The multiple-object wait functions can be instructed to return either when any one or when all of the specified objects are signaled. When a wait function returns, the waiting thread is released to continue its execution.

> The initial state of the event object is specified by the `bInitialState` parameter. Use the `SetEvent` function to set the state of an event object to signaled. Use the `ResetEvent` function to reset the state of an event object to nonsignaled.

> When the state of a manual-reset event object is signaled, it remains signaled until it is explicitly reset to nonsignaled by the `ResetEvent` function. Any number of waiting threads, or threads that subsequently begin wait operations for the specified event object, can be released while the object's state is signaled.

> When the state of an auto-reset event object is signaled, it remains signaled until a single waiting thread is released; the system then automatically resets the state to nonsignaled. If no threads are waiting, the event object's state remains signaled.

> Multiple processes can have handles of the same event object, enabling use of the object for interprocess synchronization. The following object-sharing mechanisms are available:

>> A child process created by the `CreateProcess` function can inherit a handle to an event object if the `lpEventAttributes` parameter of `CreateEvent` enabled inheritance.
>> A process can specify the event-object handle in a call to the `DuplicateHandle` function to create a duplicate handle that can be used by another process.
>> A process can specify the name of an event object in a call to the `OpenEvent` or `CreateEvent` function.

> Use the `CloseHandle` function to close the handle. The system closes the handle automatically when the process terminates. The event object is destroyed when its last handle has been closed. -->

Use `RegisterWaitForSingleObject` to check if cleaned up? Not sure.

If OK, `set_svc_status(running, no_error, 0)`

set_svc_status() handles

> `SetServiceStatus` // TODO-Doc

`CreateThread` with `start_gdipp_rpc_server`, and if can't create, stop the service.

> `CreateThread` // TODO-Doc

#### `start_gdipp_rpc_server()`

`start_gdipp_rpc_server()` is in `rpc_server.cpp`

 check if heap is ok (`process_heap = GetProcessHeap()`)
 `scoped_rw_lock::init()` // is in `./lib/scoped_rw_lock.cpp`. TODO-Code
 set `server_cache_size`
 `glyph_cache_instance.initialize()`
 `initialize_freetype()`
 multiple `rpc_status` initializations // TODO-Doc
> `RpcServerUseProtseqEp()`
> `RpcServerRegisterIf()`
> `RpcServerListen()`
> `RpcMgmtWaitServerListen()`
> // if any of these fails, stop starting rpc server

##### // textflow return to upper level

`return 0` back to `svc_init()`

If all clear, call `WTSGetActiveConsoleSessionId()` (*probably a WTL function*) for `active_session_id`.

If `active_session_id` clear, `start_hook(active_session_id)`.

### `start_hook(ULONG session_id)`

// Set the event handle inheritable.
`SECURITY_ATTRIBUTES inheritable_sa = 
{sizeof(SECURITY_ATTRIBUTES), NULL, TRUE}`
Check `WTSQueryUserToken(session_id, &h_user_token)`.
> if not, hook failure, `goto post_hook`

// Use linked token if exist, which facilitates UAC and Run As Admin.
`GetTokenInformation(h_user_token, TokenLinkedToken, &linked_token, sizeof(TOKEN_LINKED_TOKEN), &token_info_len)`
> if yes, `CloseHandle(h_user_token)`
> `h_user_token` = `linked_token.LinkedToken`

Record service process id using `GetCurrentProcessId()`.

Check `config_instance.get_number(L"/gdipp/hook/include/proc_32_bit/text()", static_cast<int>(gdipp::hook_config::PROC_32_BIT))`
> if yes, set `gdipp_hook_name` to L"gdipp_hook_32.exe"
> check (hook_proc(h_user_token, hook_env_str, gdipp_hook_name_32, pi))
>> if yes, pi_hooks_32[session_id] = pi
>> else, hook failure

Run a 64-bit version of above check.

#### `hook_proc()`

`get_dir_file_path(NULL, gdipp_hook_name, gdipp_hook_path)` // is in `./lib/helper.cpp`, appends hook_name after the module's dir

`return CreateProcessAsUserW(h_user_token, gdipp_hook_path, NULL, NULL, NULL, TRUE, NULL, hook_env_str, NULL, &si, &pi)`

##### // textflow return to upper level

`post_hook:`

if hook success, set `h_user_tokens[session_id] = h_user_token`
else, if have `h_user_token`, `CloseHandle(h_user_token)`

Return whether we have token.

[start_gdipp_rpc_server]:

[Kernel Object Namespaces]:https://msdn.microsoft.com/en-us/library/windows/desktop/aa382954(v=vs.85).aspx
[Object Namespaces]:https://msdn.microsoft.com/en-us/library/windows/desktop/ms684295(v=vs.85).aspx
[Synchronization Object Security and Access Rights]:https://msdn.microsoft.com/en-us/library/windows/desktop/ms686670(v=vs.85).aspx

## Meta Glossary

- WTL
	Windows Template Library
- RPC
	Remote Procedure Call
- SCM
	Service Controller Manager