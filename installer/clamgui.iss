; Inno Setup script.  Build:  ISCC /DGuiVer=2 /DSuiteVer=2026.11 /DClamAVVer=1.5.4 installer\clamgui.iss    (stage the payload first: tools/stage_installer.sh)
#ifndef GuiVer
  #error Pass /DGuiVer=N (the ClamGUI major version = the number in clamgui_vN)
#endif
#ifndef SuiteVer
  #define SuiteVer GuiVer
#endif
#ifndef ClamAVVer
  #define ClamAVVer "unknown"
#endif
[Setup]
; Keep this AppId forever: it is what lets a newer installer upgrade an older install in place.  Generate your own GUID once.
AppId={{00000000-0000-0000-0000-000000000000}
AppName=ClamGUI
AppVersion={#SuiteVer}
AppVerName=ClamGUI {#SuiteVer} (ClamAV {#ClamAVVer})
AppPublisher=YOUR NAME OR COMPANY
AppPublisherURL=https://example.com
DefaultDirName={autopf}\ClamGUI
DefaultGroupName=ClamGUI
OutputDir=..\build\installer
OutputBaseFilename=clamgui_v{#GuiVer}_setup_{#SuiteVer}
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
UninstallDisplayIcon={app}\clamgui_v{#GuiVer}_win64.exe
LicenseFile=licenses\LICENSE-ClamGUI.txt
WizardStyle=modern
; Code signing: define the tool once in the Inno IDE or pass  /Ssigntool="signtool sign ... $f"  on the ISCC command line
#ifdef SignToolDefined
SignTool=signtool
SignedUninstaller=yes
#endif

[Files]
Source: "..\build\stage\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\ClamGUI"; Filename: "{app}\clamgui_v{#GuiVer}_win64.exe"
Name: "{autodesktop}\ClamGUI"; Filename: "{app}\clamgui_v{#GuiVer}_win64.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop icon"

[Run]
Filename: "{app}\clamgui_v{#GuiVer}_win64.exe"; Description: "Start ClamGUI (then use the Update tab to download the virus database)"; Flags: postinstall nowait skipifsilent

[UninstallRun]
; stop and delete the background service if the user installed it from the Advanced tab
Filename: "{app}\clamgui_v{#GuiVer}_win64.exe"; Parameters: "--remove-service"; Flags: runhidden; RunOnceId: "ClamGUIRemoveService"
