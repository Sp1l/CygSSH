;This REQUIRES NSIS Modern User Interface Version 1.70 (NSIS 2.0-Final)

;OpenSSH for Windows 6.9p1-1, OpenSSL 0.9.8zf/1.0.2c-1
;Installer Script
;Written by Michael Johnson
;Updated and modified by Mark Saeger
;Based on script examples by Joost Verburg
;
;This script and related support files are licensed under the GPL

;Include ModernUI Components
!include "MUI.nsh"
!include "x64.nsh"
!include "SpecialGroupsSIDs.nsh"
!include "StrFunc.nsh"
!include "Registry.nsh"

${StrTok}
${unStrTok}

;Extra Help Files - Path Addition and Deletion Functions
!include ".\InstallerSupport\Path.nsi"
!include ".\InstallerSupport\GetParent.nsi"

;General Variables (Installer Global ONLY)
Name "OpenSSH for Windows 6.9p1-1"                   ;The name of the product
SetCompressor /SOLID /FINAL lzma                     ;Use lzma Compression
OutFile "setupssh-6.9p1-1.exe"                       ;This is the name of the output file
!packhdr tmp.dat "c:\upx\upx.exe --best -q tmp.dat"  ;Compress the NSIS header with UPX
RequestExecutionLevel admin
!define _VERSION "6.9.1.1" 							 ;must be numeric 4 digits 
!define _VERSION_NAME "6.9p1-1" 
!define _NAME "OpenSSH for Windows" 

;Interface Customization
!define "MUI_ICON" "${NSISDIR}\Contrib\Graphics\Icons\orange-install.ico"
!define "MUI_UNICON" "${NSISDIR}\Contrib\Graphics\Icons\orange-uninstall.ico"
!define "MUI_HEADERIMAGE_RIGHT"
!define "MUI_HEADERIMAGE_BITMAP" "${NSISDIR}\Contrib\Graphics\Header\orange-r.bmp"
!define "MUI_HEADERIMAGE_UNBITMAP" "${NSISDIR}\Contrib\Graphics\Header\orange-uninstall-r.bmp"
!define "MUI_WELCOMEFINISHPAGE_BITMAP" "${NSISDIR}\Contrib\Graphics\Wizard\orange.bmp"
!define "MUI_UNWELCOMEFINISHPAGE_BITMAP" "${NSISDIR}\Contrib\Graphics\Wizard\orange-uninstall.bmp"

;Variables used by the script
Var MUI_TEMP
Var STARTMENU_FOLDER
Var PRIVSEP
Var SSHDSERVER
Var SSHDPASS
Var SSHDPORT
Var SSHDDOMAIN
Var KEYSIZE
Var SSHCLIENTONLY
Var SSHSERVERONLY
Var X86FORCE

;The default install dir - The user can overwrite this later on
InstallDir "$PROGRAMFILES\OpenSSH"
	
;Check the Registry for an existing install directory choice (used in upgrades)
InstallDirRegKey HKLM "Software\OpenSSH for Windows" ""

;ModernUI Specific Interface Settings
!define MUI_ABORTWARNING                 ;Issue a warning if the user tries to reboot
;!define MUI_UI_COMPONENTSPAGE_SMALLDESC "${NSISDIR}\Contrib\UIs\modern-smalldesc.exe"  ;Show a smaller description area (under the components, instead of to the side

;StartMenu Configuration
!define MUI_STARTMENUPAGE_REGISTRY_ROOT "HKLM"
!define MUI_STARTMENUPAGE_REGISTRY_KEY "Software\OpenSSH for Windows"
!define MUI_STARTMENUPAGE_REGISTRY_VALUENAME "Start Menu Folder"

;Page Specific Settings
!define MUI_WELCOMEPAGE_TITLE_3LINES     						  ;Display the title in 3 lines 
!define MUI_STARTMENUPAGE_NODISABLE                               ;User cannot disable creation of StartMenu icons
!define MUI_LICENSEPAGE_RADIOBUTTONS                              ;Use radio buttons for license acceptance
!define MUI_FINISHPAGE_NOREBOOTSUPPORT                            ;Disable the reboot suport section for the finish page - we don't reboot anyway
!define MUI_STARTMENUPAGE_DEFAULTFOLDER "OpenSSH for Windows"     ;The default folder for the StartMenu
;!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\docs\quickstart.txt" ;The file linked as the readme

;Pages in the installer
!insertmacro MUI_PAGE_WELCOME                                 	;Welcome Page
!insertmacro MUI_PAGE_LICENSE "InstallerSupport\License.txt"  	;The license page, and the file to pull the text from
!insertmacro MUI_PAGE_COMPONENTS                              	;Software components page
!insertmacro MUI_PAGE_DIRECTORY                               	;Installation directory page
!insertmacro MUI_PAGE_STARTMENU Application $STARTMENU_FOLDER
Page custom SetupService LeaveService 							;Custom page for executing sshd as a different user
;privsep is ONLY relevant if they have chosen to run as a different user
;as the folder will be owned by sshd_server
Page custom SetupPrivSep LeavePrivSep 							;Custom page for executing priviledge seperation
Page custom SetupPort LeavePort									;Custom page for port setup
Page custom SetupKeySize LeaveKeySize							;Custom page for keysize setup
Page custom SetupPasswdGroup LeavePasswdGroup 					;Custom page for executing passwd/group setup
!insertmacro MUI_PAGE_INSTFILES                               	;Show installation progress
!insertmacro MUI_PAGE_FINISH                                  	;Display the finish page

;Pages in the uninstaller
!insertmacro MUI_UNPAGE_WELCOME    								;Show Uninstaller welcome page
!insertmacro MUI_UNPAGE_CONFIRM    								;Show uninstaller confirmation page - Does the user _really_ want to remove this awesome software?
!insertmacro MUI_UNPAGE_INSTFILES  								;Show uninstallation progress
!insertmacro MUI_UNPAGE_FINISH     								;Show uninstaller finish page

;Set the language we want the installer to be in (note this only applies for Installer-specific strings - everything else is in English)
!insertmacro MUI_LANGUAGE "English"

;VersionInfo, after MUI_LANGUAGE was set 
VIProductVersion "${_VERSION}" 
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductName" "${_NAME}_${_VERSION}" 
VIAddVersionKey /LANG=${LANG_ENGLISH} "CompanyName" "www.mls-software.com" 
VIAddVersionKey /LANG=${LANG_ENGLISH} "LegalCopyright" "Copyright (C) 2015 www.mls-software.com" 
VIAddVersionKey /LANG=${LANG_ENGLISH} "Comments" "${_NAME}_${_VERSION}" 
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileDescription" "${_NAME}_${_VERSION}" 
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileVersion" "${_VERSION}" 
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductVersion" "${_VERSION}" 
VIAddVersionKey /LANG=${LANG_ENGLISH} "InternalName" "${_NAME}.exe" 
VIAddVersionKey /LANG=${LANG_ENGLISH} "OriginalFilename" "${_NAME} ${_VERSION_NAME}.exe" 

;Installer process sections - This is where the actual install takes place
!include ".\InstallerSupport\InstallerProcess.nsi"

;Descriptions - These are used when the component is moused-over and display in the description box
!include ".\InstallerSupport\Descriptions.nsi"

;Section for uninstaller process
!include ".\InstallerSupport\UnInstallerProcess.nsi"

;Handle silent parameters
!include "FileFunc.nsh"
!insertmacro GetParameters
!insertmacro GetOptions



Function SetupPasswdGroup
	SectionGetFlags ${Server} $R0 
	IntOp $R0 $R0 & ${SF_SELECTED} 
	IntCmp $R0 ${SF_SELECTED} showSetupPasswdGroup 
 	Abort 
 showSetupPasswdGroup: 
	!insertmacro MUI_HEADER_TEXT "Choose user type for SSHD" "Choose to execute SSHD for local or domain users"
	;Display custom dialog
	Push $R0
	;assume that if we have the group file created, then we don't want to whack the users stuff 
	IfFileExists $INSTDIR\etc\group skipSetupPasswdGroup
	InstallOptions::dialog $PLUGINSDIR\openssh_grppwd.ini
skipSetupPasswdGroup:
	Pop $R0
FunctionEnd

Function LeavePasswdGroup
	;Process input (we are in usr/var at this point...)
	ReadINIStr $SSHDDOMAIN "$PLUGINSDIR\openssh_grppwd.ini" "Field 3" "State"
FunctionEnd



Function SetupPrivSep
	SectionGetFlags ${Server} $R0 
	IntOp $R0 $R0 & ${SF_SELECTED} 
	IntCmp $R0 ${SF_SELECTED} showSetupPrivSep 
	Abort 
showSetupPrivSep: 
	!insertmacro MUI_HEADER_TEXT "Choose SSHD priviledge seperation" "Choose to execute SSHD with or without priviledge seperation"
	;Display custom dialog
	Push $R0
	;only display the dialogue if the user has selected SSHDSERVER
	IntCmp $SSHDSERVER 0 skipSetupPrivSep
	InstallOptions::dialog $PLUGINSDIR\openssh_privsep.ini
skipSetupPrivSep:
	Pop $R0
FunctionEnd

Function LeavePrivSep
	Push $R0
	IntCmp $SSHDSERVER 0 skipLeavePrivSep
	ReadINIStr $PRIVSEP "$PLUGINSDIR\openssh_privsep.ini" "Field 2" "State"
skipLeavePrivSep:
	Pop $R0
FunctionEnd



Function SetupService
	SectionGetFlags ${Server} $R0 
	IntOp $R0 $R0 & ${SF_SELECTED} 
	IntCmp $R0 ${SF_SELECTED} showSetupService 
	Abort 
showSetupService: 
	!insertmacro MUI_HEADER_TEXT "Choose account under which to execute SSHD" "Choose to execute SSHD as either LOCAL_SYSTEM or SSHD_SERVER"
	;Display custom dialog
	Push $R0
	InstallOptions::dialog $PLUGINSDIR\openssh_service.ini
	Pop $R0
FunctionEnd

Function LeaveService
	ReadINIStr $0 "$PLUGINSDIR\openssh_service.ini" "Settings" "State"
	StrCmp $0 0 nextbutton
	StrCmp $0 2 disablepwd
	StrCmp $0 3 enablepwd
	Abort
disablepwd:
	;MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION "disable pwd"
	ReadINIStr $1 "$PLUGINSDIR\openssh_service.ini" "Field 4" "HWND"
	EnableWindow $1 0 ;disable the window
	ReadINIStr $1 "$PLUGINSDIR\openssh_service.ini" "Field 4" "HWND2"
	EnableWindow $1 0 ;disable the window
	Abort ;back to dialog		
enablepwd:
	;MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION "enable pwd"
	ReadINIStr $1 "$PLUGINSDIR\openssh_service.ini" "Field 4" "HWND"
	EnableWindow $1 1 ;enable the window
	ReadINIStr $1 "$PLUGINSDIR\openssh_service.ini" "Field 4" "HWND2"
	EnableWindow $1 1 ;enable the window	
	Abort ;back to dialog	
nextbutton:
	StrCpy $SSHDSERVER 0
	;Process input (we are in usr/var at this point...)
	ReadINIStr $R0 "$PLUGINSDIR\openssh_service.ini" "Field 2" "State"
	IntCmp $R0 1 end
   	ReadINIStr $SSHDPASS "$PLUGINSDIR\openssh_service.ini" "Field 4" "State"	
	StrCpy $SSHDSERVER 1
end:
FunctionEnd



Function SetupPort
	SectionGetFlags ${Server} $R0 
	IntOp $R0 $R0 & ${SF_SELECTED} 
	IntCmp $R0 ${SF_SELECTED} showSetupPort 
	Abort 
showSetupPort: 
	!insertmacro MUI_HEADER_TEXT "Choose port for SSHD daemon" "Choose port for SSDH listener daemon"
	;Display custom dialog
	Push $R0
	InstallOptions::dialog $PLUGINSDIR\openssh_port.ini
	Pop $R0
FunctionEnd

Function LeavePort
	Push $R0
  	ReadINIStr $SSHDPORT "$PLUGINSDIR\openssh_port.ini" "Field 2" "State"	
	Pop $R0
FunctionEnd


Function SetupKeySize
	SectionGetFlags ${Server} $R0 
	IntOp $R0 $R0 & ${SF_SELECTED} 
	IntCmp $R0 ${SF_SELECTED} showSetupKeySize 
	Abort 
showSetupKeySize: 
	!insertmacro MUI_HEADER_TEXT "Choose key size for key generation" "Choose key size for key generation"
	;Display custom dialog
	Push $R0
	InstallOptions::dialog $PLUGINSDIR\openssh_keysize.ini
	Pop $R0
FunctionEnd

Function LeaveKeySize
	Push $R0
  	ReadINIStr $KEYSIZE "$PLUGINSDIR\openssh_keysize.ini" "Field 2" "State"	
	Pop $R0
FunctionEnd


Function .onInit
	;default settings for variables/parameters
	StrCpy $SSHDPORT 22
	StrCpy $SSHDSERVER 0
	StrCpy $PRIVSEP 0
	StrCpy $SSHDPASS ""
	StrCpy $SSHDDOMAIN 0
	StrCpy $KEYSIZE 2048
	StrCpy $SSHCLIENTONLY 0
	StrCpy $SSHSERVERONLY 0
	StrCpy $X86FORCE 0
	
	;handle cmd line parameters
	;/port=XX    [valid port]
	;/password=serverpassword [overloaded, will run as sshd_server with serverpassword]
	;/privsep=X  [0|1] [only valid if have /server, else forced to 0]
	;/domain=X [0|1]
	;/keysize=XXXX
	;/clientonly=X [O|1] set 1 to enable client only
	;/serveronly=X [0|1] set 1 to enable server only
	;/x86=X [0|1] set 1 to enable forced x86 install
	${GetParameters} $R0
	ClearErrors
	${GetOptions} $R0 /port= $0
	${GetOptions} $R0 /password= $1
	${GetOptions} $R0 /privsep= $2
	${GetOptions} $R0 /domain= $3
    ${GetOptions} $R0 /keysize= $4
	${GetOptions} $R0 /clientonly= $5
	${GetOptions} $R0 /serveronly= $6
	${GetOptions} $R0 /x86= $7
	;only if we have values passed in would we overwrite
	StrCmp $0 "" +2
	StrCpy $SSHDPORT $0
	StrCmp $1 "" +3
	StrCpy $SSHDPASS $1
	StrCpy $SSHDSERVER 1 ;force this to on
	StrCmp $2 "" +2
	StrCpy $PRIVSEP $2
	StrCmp $3 "" +2
	StrCpy $SSHDDOMAIN $3

	;force PRIVSEP to off if the user didn't set sshd_server
	IntCmp $SSHDSERVER 1 +2
	StrCpy $PRIVSEP 0  ;force to off
	
	StrCmp $4 "" +2
	StrCpy $KEYSIZE $4
	
	StrCmp $5 "" +2
	StrCpy $SSHCLIENTONLY $5
	
	StrCmp $6 "" +2
	StrCpy $SSHSERVERONLY $6
	
	StrCmp $7 "" +2
	StrCpy $X86FORCE $7
	
	;debug
	;MessageBox MB_OK|MB_ICONINFORMATION "port=$SSHDPORT password=$SSHDPASS server=$SSHDSERVER privsep=$PRIVSEP domain=$SSHDDOMAIN keysize=$KEYSIZE CLIENTONLY=$SSHCLIENTONLY SERVERONLY=$SSHSERVERONLY x86=$X86FORCE"

	;dispaly splash screen
	;the plugins dir is automatically deleted when the installer exits
	InitPluginsDir
	File /oname=$PLUGINSDIR\splash.bmp ".\InstallerSupport\openssh.bmp"
	IfSilent skipSplash
	splash::show 1800 $PLUGINSDIR\splash
	Pop $0 ; $0 has '1' if the user closed the splash screen early,
	; '0' if everything closed normally, and '-1' if some error occurred.
skipSplash:

	StrCmp $X86FORCE 1 force0
	${If} ${RunningX64}
		SetRegView 64
		StrCpy $INSTDIR "$PROGRAMFILES64\OpenSSH"
	${Endif}
	Goto force0a
force0:
	;if we are in x64 and the user requested x86, force it to be x64
	${If} ${RunningX64}
		SetRegView 32
		${EnableX64FSRedirection}
		StrCpy $INSTDIR "$PROGRAMFILES\OpenSSH"
	${Endif}
force0a:

	;read custom fields (not displayed for silent install)
	File /oname=$PLUGINSDIR\openssh_grppwd.ini ".\InstallerSupport\openssh_grppwd.ini"
	File /oname=$PLUGINSDIR\openssh_privsep.ini ".\InstallerSupport\openssh_privsep.ini"
	File /oname=$PLUGINSDIR\openssh_service.ini ".\InstallerSupport\openssh_service.ini"
	File /oname=$PLUGINSDIR\openssh_port.ini ".\InstallerSupport\openssh_port.ini"
	File /oname=$PLUGINSDIR\openssh_keysize.ini ".\InstallerSupport\openssh_keysize.ini"

	;uninstall old version if found
  	ReadRegStr $R0 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSSH" "UninstallString"
	StrCmp $R0 "" done
	IfSilent uninst
	MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION "OpenSSH is already installed. $\n$\nClick `OK` to remove the previous version or `Cancel` to retain the previous version." IDOK uninst
	goto done ;just allow the user to continue, without doing the remove...
  
	;Run the uninstaller
uninst:
	ClearErrors
	IfSilent unsilent
 	ExecWait '$R0 /x86=$X86FORCE ?=$INSTDIR' ;Do not copy the uninstaller to a temp file
	goto uninst2
unsilent:
	ExecWait '$R0 /x86=$X86FORCE /S _?=$INSTDIR' ;Do not copy the uninstaller to a temp file and do it QUIETELY :-)
uninst2:
 	IfErrors no_remove_uninstaller
	goto done
	;You can either use Delete /REBOOTOK in the uninstaller or add some code
	;here to remove the uninstaller. Use a registry key to check
	;whether the user has chosen to uninstall. If you are using an uninstaller
	;components page, make sure all sections are uninstalled.
no_remove_uninstaller:
	IfSilent done
	MessageBox MB_OK|MB_ICONSTOP "De-installation failed..."
	;Abort
done:

	;Check for other Cygwin apps that could break

	;NOTE: update this to use a loop

	;Look for old-style SSH install
	IfFileExists "c:\ssh" PriorCygwin
	IfFileExists "d:\ssh" PriorCygwin
	IfFileExists "e:\ssh" PriorCygwin
	IfFileExists "f:\ssh" PriorCygwin

	;Look for Cygwin install
	IfFileExists "c:\cygwin" PriorCygwin
	IfFileExists "d:\cygwin" PriorCygwin
	IfFileExists "e:\cygwin" PriorCygwin
	IfFileExists "f:\cygwin" PriorCygwin

	;Look for the Cygwin mounts registry structure
	ReadRegStr $7 HKLM "SOFTWARE\Cygnus Solutions\Cygwin\mounts v2\/" "native"

	;Look and see if read failed (good thing)
	IfErrors ContinueInstall PriorCygwin

	;Error messsage and question user
PriorCygwin:
	;Prompt. Ask if user wants to continue
	IfSilent ContinueInstall
	MessageBox MB_YESNO|MB_ICONINFORMATION "It appears that either cygwin or an earlier version of the OpenSSH for Windows package is installed, because setup is detecting Cygwin registry mounts (HKLM\SOFTWARE\Cygnus Solutions\...). If you're upgrading an OpenSSH for Windows package you can ignore this, but if not you should stop the installation.  Keep going?" IDYES ContinueInstall
	;If user does not want to continue, quit
	Quit

	;Continue Installation, called if no prior cygwin or user wants to continue
ContinueInstall:
	;Set output to the ssh subdirectory of the install path
	SetOutPath $TEMP\bin

	;Add the cygwin service runner to the output directory
	StrCmp $X86FORCE 1 force1
	${If} ${RunningX64}
		File bin64\cygrunsrv.exe
		File bin64\cygwin1.dll
	${Else}
force1:
		File bin32\cygrunsrv.exe
		File bin32\cygwin1.dll
	${EndIf}
	
	;Find out if the OpenSSHd Service is installed
	Push 'OpenSSHd'
	Services::IsServiceInstalled
	Pop $0
	; $0 now contains either 'Yes', 'No' or an error description
	StrCmp $0 'Yes' RemoveServices SkipRemoval

	;This will stop and remove the OpenSSHd service if it is running.
RemoveServices:
	push 'OpenSSHd'
	push 'Stop'
	Services::SendServiceCommand

	push 'OpenSSHd'
	push 'Delete'
	Services::SendServiceCommand
	Pop $0
	StrCmp $0 'Ok' Success
	IfSilent Success
	MessageBox MB_OK|MB_ICONSTOP 'The installer found the OpenSSH for Windows service, but was unable to remove it. Please stop it and manually remove it. Then try installing again.'
	Abort
	;now delete the user account that was associated with the sshd_server
Success:
	ExpandEnvStrings $0 %COMSPEC%
	ExecWait `"$0" /C net user sshd_server /delete`		;delete account
	ExecWait `"$0" /C net localgroup Administrators sshd_server /delete`

SkipRemoval:
FunctionEnd


Function .onInstSuccess
	; could also set user home dir here

	;Find out if the OpenSSHd Service is installed
	Push 'OpenSSHd'
	Services::IsServiceInstalled
	Pop $0
	; $0 now contains either 'Yes', 'No' or an error description
	StrCmp $0 'Yes' StartService SkipStart

	;This will start OpenSSHd service if it is running.
StartService:
	push 'OpenSSHd'
	push 'Start'
	Services::SendServiceCommand
	Pop $0
SkipStart:
FunctionEnd


Function WriteSshdConfig
	;at this point, can re-write out the sshd_config file
	SetOutPath $INSTDIR\etc
	FileOpen $9 sshd_config w ;Opens a Empty File an fills it
	FileWrite $9 "#	$$OpenBSD: sshd_config,v 1.93 2014/01/10 05:59:19 djm Exp $$"
	FileWrite $9 "$\r$\n"
	FileWrite $9 "# This is the sshd server system-wide configuration file.  See$\r$\n"
	FileWrite $9 "# sshd_config(5) for more information.$\r$\n"
	FileWrite $9 "$\r$\n"
	FileWrite $9 "# This sshd was compiled with PATH=/bin:/usr/sbin:/sbin:/usr/bin$\r$\n"
	FileWrite $9 "$\r$\n"
	FileWrite $9 "# The strategy used for options in the default sshd_config shipped with$\r$\n"
	FileWrite $9 "# OpenSSH is to specify options with their default value where$\r$\n"
	FileWrite $9 "# possible, but leave them commented.  Uncommented options change a$\r$\n"
	FileWrite $9 "# default value.$\r$\n"
	FileWrite $9 "$\r$\n"
	FileWrite $9 "Port $SSHDPORT$\r$\n"
	FileWrite $9 "#AddressFamily any$\r$\n"
	FileWrite $9 "#ListenAddress 0.0.0.0$\r$\n"
	FileWrite $9 "#ListenAddress ::$\r$\n"
	FileWrite $9 "$\r$\n"
	FileWrite $9 "# The default requires explicit activation of protocol 1$\r$\n"
	FileWrite $9 "#Protocol 2$\r$\n"
	FileWrite $9 "$\r$\n"
	FileWrite $9 "# HostKey for protocol version 1$\r$\n"
	FileWrite $9 "#HostKey /etc/ssh_host_key$\r$\n"
	FileWrite $9 "# HostKeys for protocol version 2$\r$\n"
	FileWrite $9 "#HostKey /etc/ssh_host_rsa_key$\r$\n"
	FileWrite $9 "#HostKey /etc/ssh_host_dsa_key$\r$\n"
	FileWrite $9 "#HostKey /etc/ssh_host_ecdsa_key$\r$\n"
	FileWrite $9 "#HostKey /etc/ssh_host_ed25519_key$\r$\n"
	FileWrite $9 "$\r$\n"
	FileWrite $9 "# Lifetime and size of ephemeral version 1 server key$\r$\n"
	FileWrite $9 "#KeyRegenerationInterval 1h$\r$\n"
	FileWrite $9 "#ServerKeyBits 1024$\r$\n"
	FileWrite $9 "$\r$\n"
	FileWrite $9 "# Ciphers and keying$\r$\n"
	FileWrite $9 "#RekeyLimit default none$\r$\n"
	FileWrite $9 "$\r$\n"
	FileWrite $9 "# Logging$\r$\n"
	FileWrite $9 "#obsoletes QuietMode and FascistLogging$\r$\n"
	FileWrite $9 "#SyslogFacility AUTH$\r$\n"
	FileWrite $9 "#LogLevel INFO$\r$\n"
	FileWrite $9 "$\r$\n"
	FileWrite $9 "# Authentication:$\r$\n"
	FileWrite $9 "$\r$\n"
	FileWrite $9 "#LoginGraceTime 2m$\r$\n"
	FileWrite $9 "PermitRootLogin yes$\r$\n"
	FileWrite $9 "StrictModes yes$\r$\n"
	FileWrite $9 "#MaxAuthTries 6$\r$\n"
	FileWrite $9 "#MaxSessions 10$\r$\n"
	FileWrite $9 "$\r$\n"
	FileWrite $9 "RSAAuthentication yes$\r$\n"
	FileWrite $9 "#PubkeyAuthentication yes$\r$\n"
	FileWrite $9 "$\r$\n"
	FileWrite $9 "# The default is to check both .ssh/authorized_keys and .ssh/authorized_keys2$\r$\n"
	FileWrite $9 "# but this is overridden so installations will only check .ssh/authorized_keys$\r$\n"
	FileWrite $9 "#AuthorizedKeysFile	.ssh/authorized_keys$\r$\n"
	FileWrite $9 "$\r$\n"
	FileWrite $9 "#AuthorizedPrincipalsFile none$\r$\n"
	FileWrite $9 "$\r$\n"
	FileWrite $9 "#AuthorizedKeysCommand none$\r$\n"
	FileWrite $9 "#AuthorizedKeysCommandUser nobody$\r$\n"
	FileWrite $9 "$\r$\n"
	FileWrite $9 "# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts$\r$\n"
	FileWrite $9 "#RhostsRSAAuthentication no$\r$\n"
	FileWrite $9 "# similar for protocol version 2$\r$\n"
	FileWrite $9 "#HostbasedAuthentication no$\r$\n"
	FileWrite $9 "# Change to yes if you don't trust ~/.ssh/known_hosts for$\r$\n"
	FileWrite $9 "# RhostsRSAAuthentication and HostbasedAuthentication$\r$\n"
	FileWrite $9 "IgnoreUserKnownHosts yes$\r$\n"
	FileWrite $9 "# Don't read the user's ~/.rhosts and ~/.shosts files$\r$\n"
	FileWrite $9 "#IgnoreRhosts yes$\r$\n"
	FileWrite $9 "$\r$\n"
	FileWrite $9 "# To disable tunneled clear text passwords, change to no here!$\r$\n"
	FileWrite $9 "PasswordAuthentication yes$\r$\n"
	FileWrite $9 "#PermitEmptyPasswords no$\r$\n"
	FileWrite $9 "$\r$\n"
	FileWrite $9 "# Change to no to disable s/key passwords$\r$\n"
	FileWrite $9 "#ChallengeResponseAuthentication yes$\r$\n"
	FileWrite $9 "$\r$\n"
	FileWrite $9 "# Kerberos options$\r$\n"
	FileWrite $9 "#KerberosAuthentication no$\r$\n"
	FileWrite $9 "#KerberosOrLocalPasswd yes$\r$\n"
	FileWrite $9 "#KerberosTicketCleanup yes$\r$\n"
	FileWrite $9 "#KerberosGetAFSToken no$\r$\n"
	FileWrite $9 "$\r$\n"
	FileWrite $9 "# GSSAPI options$\r$\n"
	FileWrite $9 "#GSSAPIAuthentication no$\r$\n"
	FileWrite $9 "#GSSAPICleanupCreds yes$\r$\n"
	FileWrite $9 "$\r$\n"
	FileWrite $9 "# Set this to 'yes' to enable PAM authentication, account processing,$\r$\n"
	FileWrite $9 "# and session processing. If this is enabled, PAM authentication will$\r$\n"
	FileWrite $9 "# be allowed through the ChallengeResponseAuthentication and$\r$\n"
	FileWrite $9 "# PasswordAuthentication.  Depending on your PAM configuration,$\r$\n"
	FileWrite $9 "# PAM authentication via ChallengeResponseAuthentication may bypass$\r$\n"
	FileWrite $9 "# the setting of 'PermitRootLogin without-password'.$\r$\n"
	FileWrite $9 "# If you just want the PAM account and session checks to run without$\r$\n"
	FileWrite $9 "# PAM authentication, then enable this but set PasswordAuthentication$\r$\n"
	FileWrite $9 "# and ChallengeResponseAuthentication to 'no'.$\r$\n"
	FileWrite $9 "#UsePAM yes$\r$\n"
	FileWrite $9 "$\r$\n"
	FileWrite $9 "#AllowAgentForwarding yes$\r$\n"
	FileWrite $9 "#AllowTcpForwarding yes$\r$\n"
	FileWrite $9 "#GatewayPorts no$\r$\n"
	FileWrite $9 "#X11Forwarding no$\r$\n"
	FileWrite $9 "#X11DisplayOffset 10$\r$\n"
	FileWrite $9 "#X11UseLocalhost yes$\r$\n"
	FileWrite $9 "#PrintMotd yes$\r$\n"
	FileWrite $9 "#PrintLastLog yes$\r$\n"
	FileWrite $9 "#TCPKeepAlive yes$\r$\n"
	FileWrite $9 "#UseLogin no$\r$\n"
	StrCmp $PRIVSEP 1 +3				;if PRIVSEP==1, the set as yes(sandbox now), else as no
	FileWrite $9 "UsePrivilegeSeparation no$\r$\n"
	goto +2
	FileWrite $9 "UsePrivilegeSeparation sandbox$\r$\n"
	FileWrite $9 "#PermitUserEnvironment no$\r$\n"
	FileWrite $9 "#Compression delayed$\r$\n"
	FileWrite $9 "#ClientAliveInterval 0$\r$\n"
	FileWrite $9 "#ClientAliveCountMax 3$\r$\n"
	FileWrite $9 "#UseDNS yes$\r$\n"
	FileWrite $9 "#PidFile /var/run/sshd.pid$\r$\n"
	FileWrite $9 "MaxStartups 10:30:100$\r$\n"
	FileWrite $9 "#PermitTunnel no$\r$\n"
	FileWrite $9 "#ChrootDirectory none$\r$\n"
	FileWrite $9 "#VersionAddendum none	$\r$\n"
	FileWrite $9 "$\r$\n"
	FileWrite $9 "# default banner path$\r$\n"
	FileWrite $9 "Banner /etc/banner.txt$\r$\n"
	FileWrite $9 "$\r$\n"
	FileWrite $9 "# override default of no subsystems$\r$\n"
	FileWrite $9 "Subsystem	sftp	/usr/sbin/sftp-server$\r$\n"
	FileClose $9 ;Closes the filled file
FunctionEnd