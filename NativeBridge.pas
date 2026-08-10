unit NativeBridge;

interface

uses
  Winapi.Windows;

const
  PAGE_NOACCESS          = $01;
  PAGE_READONLY          = $02;
  PAGE_READWRITE         = $04;
  PAGE_WRITECOPY         = $08;
  PAGE_EXECUTE           = $10;
  PAGE_EXECUTE_READ      = $20;
  PAGE_EXECUTE_READWRITE = $40;

function InvokeNativeAllocation(ProcessId: DWORD; out OutAddress: DWORD_PTR; Size: SIZE_T; Protect: DWORD): BOOL; stdcall;
  external 'SysGateway.dll' name 'InvokeNativeAllocation';

function InvokeNativeMemoryWrite(ProcessId: DWORD; TargetAddress: DWORD_PTR; LocalBuffer: PVoid; Size: SIZE_T; var BytesWritten: SIZE_T): BOOL; stdcall;
  external 'SysGateway.dll' name 'InvokeNativeMemoryWrite';

function InvokeNativeMemoryRead(ProcessId: DWORD; TargetAddress: DWORD_PTR; LocalBuffer: PVoid; Size: SIZE_T; var BytesRead: SIZE_T): BOOL; stdcall;
  external 'SysGateway.dll' name 'InvokeNativeMemoryRead';

function FindTargetProcessId(ProcessName: PWideChar): DWORD; stdcall;
  external 'SysGateway.dll' name 'FindTargetProcessId';

implementation

end.
