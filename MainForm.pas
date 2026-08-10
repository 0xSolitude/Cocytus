unit MainForm;

interface

uses
  Winapi.Windows, System.SysUtils, System.Classes, Vcl.Controls, Vcl.Forms, 
  Vcl.StdCtrls, NativeBridge, ServerController;

type
  TMainAppForm = class(TForm)
    BtnTargetRun: TButton;
    LogMemo: TMemo;
    EdtProcessName: TEdit;
    BtnReadWriteTest: TButton;
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure BtnTargetRunClick(Sender: TObject);
    procedure BtnReadWriteTestClick(Sender: TObject);
  private
    FServer: TServerController;
    FTargetPID: DWORD;
  public
  end;

var
  MainAppForm: TMainAppForm;

implementation

{$R *.dfm}

procedure TMainAppForm.FormCreate(Sender: TObject);
begin
  LogMemo.Clear;
  LogMemo.Lines.Add('[*] Initializing Framework Client Infrastructure...');
  FServer := TServerController.Create('http://127.0.0');
  
  if FServer.AuthenticateMachine('GLOBAL_HARDWARE_FINGERPRINT_VALUE_64') then
    LogMemo.Lines.Add('[+] Remote Authentication Established. Token Verification Active.')
  else
    LogMemo.Lines.Add('[-] Core Network Control Module Validation Unregistered.');
end;

procedure TMainAppForm.FormDestroy(Sender: TObject);
begin
  FServer.Free;
end;

procedure TMainAppForm.BtnTargetRunClick(Sender: TObject);
var
  ProcName: string;
begin
  ProcName := EdtProcessName.Text;
  if ProcName = '' then Exit;

  LogMemo.Lines.Add('[*] Locating remote application execution state...');
  FTargetPID := FindTargetProcessId(PWideChar(ProcName));
  
  if FTargetPID <> 0 then
  begin
    LogMemo.Lines.Add('[+] Application Hook Found. Process Target ID Logged: ' + IntToStr(FTargetPID));
    FServer.SendTelemetryLog('PROCESS_HOOK', 'Successfully targeting process PID: ' + IntToStr(FTargetPID));
  end else
    LogMemo.Lines.Add('[-] Selected Target instance is not actively running.');
end;

procedure TMainAppForm.BtnReadWriteTestClick(Sender: TObject);
var
  RemoteAddress: DWORD_PTR;
  LocalPayload: array[0..3] of Byte;
  VerificationBuffer: array[0..3] of Byte;
  BytesTransfered: SIZE_T;
begin
  if FTargetPID = 0 then
  begin
    LogMemo.Lines.Add('[-] Active operational Process ID target is required.');
    Exit;
  end;

  LocalPayload := $DE; LocalPayload := $AD; LocalPayload := $BE; LocalPayload := $EF;

  LogMemo.Lines.Add('[*] Deploying system calls...');
  if InvokeNativeAllocation(FTargetPID, RemoteAddress, 4096, PAGE_EXECUTE_READWRITE) then
  begin
    LogMemo.Lines.Add('[+] Block created inside memory coordinates: 0x' + IntToHex(RemoteAddress, 16));
    
    if InvokeNativeMemoryWrite(FTargetPID, RemoteAddress, @LocalPayload, 4, BytesTransfered) then
    begin
      LogMemo.Lines.Add('[+] Byte arrays passed directly into target application allocation state.');
      
      if InvokeNativeMemoryRead(FTargetPID, RemoteAddress, @VerificationBuffer, 4, BytesTransfered) then
      begin
        LogMemo.Lines.Add('[+] Remote verification sweep executed: ' + 
          IntToHex(VerificationBuffer, 2) + IntToHex(VerificationBuffer, 2) +
          IntToHex(VerificationBuffer, 2) + IntToHex(VerificationBuffer, 2));
      end;
    end;
  end else
    LogMemo.Lines.Add('[-] Target application spatial allocation failed.');
end;

end.
