; StreamTokLive one-click per-machine installer.
; Exact install directory: C:\Program Files\StreamTokLive [V]

!macro customInstallMode
  StrCpy $isForceCurrentInstall "0"
  StrCpy $isForceMachineInstall "1"
!macroend

!macro preInit
  SetRegView 64
  WriteRegExpandStr HKLM "${INSTALL_REGISTRY_KEY}" InstallLocation "$PROGRAMFILES64\StreamTokLive [V]"
  WriteRegExpandStr HKCU "${INSTALL_REGISTRY_KEY}" InstallLocation "$PROGRAMFILES64\StreamTokLive [V]"

  SetRegView 32
  WriteRegExpandStr HKLM "${INSTALL_REGISTRY_KEY}" InstallLocation "$PROGRAMFILES64\StreamTokLive [V]"
  WriteRegExpandStr HKCU "${INSTALL_REGISTRY_KEY}" InstallLocation "$PROGRAMFILES64\StreamTokLive [V]"
!macroend

!macro customInit
  SetSilent silent
  SetAutoClose true
!macroend
