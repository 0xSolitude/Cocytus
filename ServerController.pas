unit ServerController;

interface

uses
  System.SysUtils, System.Classes, System.Net.HttpClient, System.Net.URLClient, System.JSON;

type
  TServerController = class
  private
    FClient: THTTPClient;
    FServerURL: string;
    FSessionToken: string;
  public
    constructor Create(const APIUrl: string);
    destructor Destroy; override;
    function AuthenticateMachine(const HardwareKey: string): BOOL;
    function SendTelemetryLog(const ActionType, LogMessage: string): BOOL;
    property SessionToken: string read FSessionToken;
  end;

implementation

constructor TServerController.Create(const APIUrl: string);
begin
  inherited Create;
  FClient := THTTPClient.Create;
  FClient.ContentType := 'application/x-www-form-urlencoded';
  FServerURL := APIUrl;
  FSessionToken := '';
end;

destructor TServerController.Destroy;
begin
  FClient.Free;
  inherited Destroy;
end;

function TServerController.AuthenticateMachine(const HardwareKey: string): BOOL;
var
  Params: TStringList;
  Response: IHTTPResponse;
  JSONObj: TJSONObject;
  StatusStr: string;
begin
  Result := False;
  Params := TStringList.Create;
  try
    Params.Add('hwid=' + HardwareKey);
    try
      Response := FClient.Post(FServerURL + '/auth.php', Params);
      if Response.StatusCode = 200 then
      begin
        JSONObj := TJSONObject.ParseJSONValue(Response.ContentAsString) as TJSONObject;
        if Assigned(JSONObj) then
        begin
          try
            if JSONObj.TryGetValue<string>('status', StatusStr) and (StatusStr = 'success') then
            begin
              JSONObj.TryGetValue<string>('token', FSessionToken);
              Result := True;
            end;
          finally
            JSONObj.Free;
          end;
        end;
      end;
    except
    end;
  finally
    Params.Free;
  end;
end;

function TServerController.SendTelemetryLog(const ActionType, LogMessage: string): BOOL;
var
  Params: TStringList;
  Response: IHTTPResponse;
begin
  Result := False;
  if FSessionToken = '' then Exit;

  Params := TStringList.Create;
  try
    Params.Add('token=' + FSessionToken);
    Params.Add('action=' + ActionType);
    Params.Add('log=' + LogMessage);
    try
      Response := FClient.Post(FServerURL + '/telemetry.php', Params);
      Result := (Response.StatusCode = 200);
    except
    end;
  finally
    Params.Free;
  end;
end;

end.
