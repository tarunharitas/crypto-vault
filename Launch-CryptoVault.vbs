Set WshShell = CreateObject("WScript.Shell")
strPath = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)
WshShell.Run chr(34) & strPath & "\.venv\Scripts\pythonw.exe" & chr(34) & " " & chr(34) & strPath & "\main_gui.py" & chr(34), 0, False
Set WshShell = Nothing
