; Windows setup program for the service dashboard.
; Build: ISCC /DMyAppVersion=1.0.1 installer\windows\svcdash.iss

#ifndef MyAppVersion
  #define MyAppVersion "1.0.1"
#endif

#define MyAppName "Service Dashboard"
#define MyAppPublisher "JaredScar"
#define MyAppURL "https://github.com/JaredScar/LocalServiceManager"

[Setup]
AppId={{7C4E9A2B-1F63-4D85-9A0E-6B2C8F4D1E77}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
DefaultDirName=C:\apps\svcdash
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=..\..\dist
OutputBaseFilename=ServiceDashboard-Setup
SetupIconFile=..\assets\svcdash.ico
UninstallDisplayIcon={app}\svcdash.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
CloseApplications=no
MinVersion=10.0
ChangesAssociations=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "..\assets\svcdash.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\server.js"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\collect.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\install.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "uninstall.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\config.example.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\lib\*"; DestDir: "{app}\lib"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\..\public\*"; DestDir: "{app}\public"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\..\config.example.json"; DestDir: "{app}"; DestName: "config.json"; Flags: onlyifdoesntexist uninsneveruninstall

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{win}\explorer.exe"; Parameters: "http://127.0.0.1:3090"; IconFilename: "{app}\svcdash.ico"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{win}\explorer.exe"; Parameters: "http://127.0.0.1:3090"; IconFilename: "{app}\svcdash.ico"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Add a desktop shortcut"; GroupDescription: "Shortcuts:"

[UninstallRun]
Filename: "powershell.exe"; Parameters: "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ""{app}\uninstall.ps1"""; Flags: runhidden waituntilterminated

[Run]
Filename: "http://127.0.0.1:3090"; Description: "Open the dashboard"; Flags: postinstall shellexec runasoriginaluser nowait skipifsilent unchecked; Check: ShouldOpenDashboard

[Code]
var
  CreatedConfig: Boolean;

function NodeExe(Param: String): String;
begin
  Result := ExpandConstant('{pf}\nodejs\node.exe');
end;

function ShouldOpenDashboard: Boolean;
begin
  Result := not CreatedConfig;
end;

function InitializeSetup(): Boolean;
var
  Code: Integer;
begin
  Result := True;
  if not FileExists(NodeExe('')) then
  begin
    MsgBox('Install Node.js 18 or newer first. The official installer puts node.exe in "C:\Program Files\nodejs".', mbError, MB_OK);
    Result := False;
    Exit;
  end;
  if not Exec(ExpandConstant('{sys}\where.exe'), 'nssm', '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
  begin
    MsgBox('Install NSSM and open a new window so nssm.exe is on PATH, then run this setup again.', mbError, MB_OK);
    Result := False;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  Result := '';
  NeedsRestart := False;
  Exec('powershell.exe', '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Stop-Service svcdash -Force -ErrorAction SilentlyContinue"', '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Code: Integer;
  Params: String;
begin
  if CurStep = ssInstall then
    CreatedConfig := not FileExists(ExpandConstant('{app}\config.json'));

  if CurStep <> ssPostInstall then
    Exit;

  if CreatedConfig then
  begin
    MsgBox('Created ' + ExpandConstant('{app}\config.json') + '.' + #13#10 + #13#10 + 'Edit it, using forward slashes in paths, then run ' + ExpandConstant('{app}\install.ps1') + ' from an elevated PowerShell.', mbInformation, MB_OK);
    Exit;
  end;

  Params := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\install.ps1') + '" -Dir "' + ExpandConstant('{app}') + '" -Node "' + NodeExe('') + '"';
  if (not Exec('powershell.exe', Params, '', SW_SHOWNORMAL, ewWaitUntilTerminated, Code)) or (Code <> 0) then
    MsgBox('The files are in place, but registering the service failed. Run ' + ExpandConstant('{app}\install.ps1') + ' from an elevated PowerShell to see the error.', mbError, MB_OK);
end;
