Remove-Item -path 'C:\programdata\microsoft\windows\start menu\programs\startup\kscunlock.vbs'
Remove-Item -path 'c:\temp\lockdown.vbs'
Remove-Item -path 'c:\temp\key.txt'
schtasks /delete /tn ksclockdown /f
schtasks /delete /tn kscreboot /f