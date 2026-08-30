Unicode true
SetCompressor /SOLID lzma

!ifndef PRODUCT_VERSION
  !error "PRODUCT_VERSION must be supplied by the packaging script"
!endif
!ifndef STAGE_DIR
  !error "STAGE_DIR must be supplied by the packaging script"
!endif
!ifndef OUTPUT_FILE
  !error "OUTPUT_FILE must be supplied by the packaging script"
!endif

!define PRODUCT_NAME "ConMan"
!define PRODUCT_DISPLAY_NAME "Connection Manager"
!define PRODUCT_PUBLISHER "MarcoS0ft"
!define PRODUCT_URL "https://github.com/MarcoS0ft/conman"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"

; MultiUser supplies the install-mode page, the correct Program Files location,
; shell context, and matching uninstaller context. /CurrentUser and /AllUsers
; are also available for unattended deployments.
!define MULTIUSER_EXECUTIONLEVEL Highest
!define MULTIUSER_MUI
!define MULTIUSER_INSTALLMODE_COMMANDLINE
!define MULTIUSER_INSTALLMODE_INSTDIR "${PRODUCT_NAME}"
!define MULTIUSER_USE_PROGRAMFILES64
!define MULTIUSER_INSTALLMODE_INSTDIR_REGISTRY_KEY "${UNINSTALL_KEY}"
!define MULTIUSER_INSTALLMODE_INSTDIR_REGISTRY_VALUENAME "InstallLocation"
!define MULTIUSER_INSTALLMODE_DEFAULT_REGISTRY_KEY "${UNINSTALL_KEY}"
!define MULTIUSER_INSTALLMODE_DEFAULT_REGISTRY_VALUENAME "CurrentUser"

!include "LogicLib.nsh"
!include "x64.nsh"
!include "WinVer.nsh"
!include "MultiUser.nsh"
!include "MUI2.nsh"
!include "WinMessages.nsh"

Name "${PRODUCT_DISPLAY_NAME}"
OutFile "${OUTPUT_FILE}"
BrandingText " "
ShowInstDetails show
ShowUninstDetails show

!define MUI_ABORTWARNING
!define MUI_ICON "..\..\resources\ConMan.ico"
!define MUI_UNICON "..\..\resources\ConMan.ico"
!define MUI_FINISHPAGE_RUN "$INSTDIR\conman.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Launch ${PRODUCT_DISPLAY_NAME}"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MULTIUSER_PAGE_INSTALLMODE
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Var CommandLineInstDir

Function .onInit
  ${IfNot} ${AtLeastWin10}
    MessageBox MB_OK|MB_ICONSTOP "${PRODUCT_DISPLAY_NAME} requires Windows 10 or later."
    SetErrorLevel 1
    Quit
  ${EndIf}
  ${IfNot} ${RunningX64}
    MessageBox MB_OK|MB_ICONSTOP "This package requires 64-bit Windows."
    SetErrorLevel 1
    Quit
  ${EndIf}
  ; NSIS applies /D before .onInit, while MultiUser chooses its default path
  ; during initialization. Preserve an explicit unattended install directory
  ; across that default selection; interactive installs still begin at the
  ; scope-appropriate Program Files location.
  StrCpy $CommandLineInstDir $INSTDIR
  !insertmacro MULTIUSER_INIT
  ${If} $CommandLineInstDir != ""
    StrCpy $INSTDIR $CommandLineInstDir
  ${EndIf}
  SetRegView 64
FunctionEnd

Function un.onInit
  !insertmacro MULTIUSER_UNINIT
  SetRegView 64
FunctionEnd

Section "Connection Manager" SecConMan
  SectionIn RO
  SetOverwrite on

  SetOutPath "$INSTDIR"
  File "${STAGE_DIR}\conman.exe"
  File "${STAGE_DIR}\ghostty-vt.dll"
  File "update-path.ps1"

  ; Keep the CLI in its own directory. The same directory is added to the PATH
  ; for the selected install scope and removed again by the uninstaller.
  SetOutPath "$INSTDIR\bin"
  File "${STAGE_DIR}\conmanctl.exe"

  SetOutPath "$INSTDIR\licenses"
  File /oname=LICENSE-MIT "..\..\LICENSE-MIT"
  File /oname=LICENSE-APACHE "..\..\LICENSE-APACHE"
  File /oname=NOTICE.md "..\..\crates\cm-ui\assets\fonts\NOTICE.md"
  File /oname=JetBrainsMono-OFL.txt "..\..\crates\cm-ui\assets\fonts\JetBrainsMono-OFL.txt"
  File /oname=SymbolsNerdFont-LICENSE-MIT.txt "..\..\crates\cm-ui\assets\fonts\SymbolsNerdFont-LICENSE-MIT.txt"

  SetOutPath "$INSTDIR"
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  CreateShortCut "$SMPROGRAMS\${PRODUCT_DISPLAY_NAME}.lnk" \
    "$INSTDIR\conman.exe" "" "$INSTDIR\conman.exe" 0

  ${If} $MultiUser.InstallMode == "AllUsers"
    DetailPrint "Adding $INSTDIR\bin to the system PATH"
    StrCpy $1 "Machine"
  ${Else}
    DetailPrint "Adding $INSTDIR\bin to the user PATH"
    StrCpy $1 "User"
  ${EndIf}
  nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\update-path.ps1" -Action Add -Scope $1 -Entry "$INSTDIR\bin"'
  Pop $0
  Pop $2
  ${If} $0 == 0
    WriteRegDWORD ShCtx "${UNINSTALL_KEY}" "PathEntryAdded" 1
    WriteRegStr ShCtx "${UNINSTALL_KEY}" "PathAddMode" "AddedSeparator"
  ${ElseIf} $0 == 11
    WriteRegDWORD ShCtx "${UNINSTALL_KEY}" "PathEntryAdded" 1
    WriteRegStr ShCtx "${UNINSTALL_KEY}" "PathAddMode" "TrailingSeparator"
  ${ElseIf} $0 == 12
    WriteRegDWORD ShCtx "${UNINSTALL_KEY}" "PathEntryAdded" 1
    WriteRegStr ShCtx "${UNINSTALL_KEY}" "PathAddMode" "OnlyEntry"
  ${ElseIf} $0 == 10
    WriteRegDWORD ShCtx "${UNINSTALL_KEY}" "PathEntryAdded" 0
  ${Else}
    MessageBox MB_OK|MB_ICONSTOP "Could not add conmanctl to the $1 PATH (exit $0).$\n$2"
    Abort
  ${EndIf}
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000

  ; ShCtx resolves to HKLM or HKCU using the mode chosen above. The value whose
  ; name is the mode is the stock MultiUser marker used by the uninstaller.
  WriteRegStr ShCtx "${UNINSTALL_KEY}" "$MultiUser.InstallMode" "1"
  WriteRegStr ShCtx "${UNINSTALL_KEY}" "DisplayName" "${PRODUCT_DISPLAY_NAME}"
  WriteRegStr ShCtx "${UNINSTALL_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr ShCtx "${UNINSTALL_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
  WriteRegStr ShCtx "${UNINSTALL_KEY}" "URLInfoAbout" "${PRODUCT_URL}"
  WriteRegStr ShCtx "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\conman.exe"
  WriteRegStr ShCtx "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr ShCtx "${UNINSTALL_KEY}" "UninstallString" '$\"$INSTDIR\Uninstall.exe$\"'
  WriteRegDWORD ShCtx "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD ShCtx "${UNINSTALL_KEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  ReadRegDWORD $2 ShCtx "${UNINSTALL_KEY}" "PathEntryAdded"
  ${If} $2 == 1
    ReadRegStr $2 ShCtx "${UNINSTALL_KEY}" "PathAddMode"
    ${If} $MultiUser.InstallMode == "AllUsers"
      DetailPrint "Removing $INSTDIR\bin from the system PATH"
      StrCpy $1 "Machine"
    ${Else}
      DetailPrint "Removing $INSTDIR\bin from the user PATH"
      StrCpy $1 "User"
    ${EndIf}
    nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\update-path.ps1" -Action Remove -Scope $1 -Entry "$INSTDIR\bin" -RemoveMode $2'
    Pop $0
    Pop $3
    ${If} $0 != 0
    ${AndIf} $0 != 10
      MessageBox MB_OK|MB_ICONSTOP "Could not remove conmanctl from the $1 PATH (exit $0).$\n$3"
      Abort
    ${EndIf}
    SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
  ${EndIf}

  Delete "$SMPROGRAMS\${PRODUCT_DISPLAY_NAME}.lnk"
  Delete "$INSTDIR\bin\conmanctl.exe"
  RMDir "$INSTDIR\bin"
  Delete "$INSTDIR\conman.exe"
  Delete "$INSTDIR\ghostty-vt.dll"
  Delete "$INSTDIR\update-path.ps1"
  Delete "$INSTDIR\licenses\LICENSE-MIT"
  Delete "$INSTDIR\licenses\LICENSE-APACHE"
  Delete "$INSTDIR\licenses\NOTICE.md"
  Delete "$INSTDIR\licenses\JetBrainsMono-OFL.txt"
  Delete "$INSTDIR\licenses\SymbolsNerdFont-LICENSE-MIT.txt"
  RMDir "$INSTDIR\licenses"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey ShCtx "${UNINSTALL_KEY}"
SectionEnd
