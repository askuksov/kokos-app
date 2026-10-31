; Uninstaller hook: offer to remove what Kokos stored outside its install
; folder — saved master passwords and Google Drive tokens in Credential
; Manager, and the browser native-messaging registration. Vault files are
; never touched.
;
; It runs before any file is deleted, so kokos.exe is still here to do the
; work. It stays silent when a newer installer runs this uninstaller as part
; of an upgrade: that happens in place (_?=$INSTDIR), so $EXEDIR equals
; $INSTDIR, while a normal uninstall first copies itself to %TEMP%.
; A silent uninstall (/S) takes the default answer, Yes.
;
; The prompt is a plain string: this file is included before the installer's
; languages are defined, and the installer is English-only.

!macro NSIS_HOOK_PREUNINSTALL
  ${If} $UpdateMode <> 1
  ${AndIf} "$EXEDIR" != "$INSTDIR"
    ClearErrors
    ExecWait '"$INSTDIR\${MAINBINARYNAME}.exe" --uninstall-scan' $0
    ${IfNot} ${Errors}
    ${AndIf} $0 <> 0
      MessageBox MB_YESNO|MB_ICONQUESTION \
        "Kokos saved master passwords or browser registrations on this computer.$\r$\n$\r$\nRemove them too? Your vault files are not affected." \
        /SD IDYES IDNO kokos_skip_purge
      ExecWait '"$INSTDIR\${MAINBINARYNAME}.exe" --uninstall-purge'
      kokos_skip_purge:
    ${EndIf}
  ${EndIf}
!macroend
