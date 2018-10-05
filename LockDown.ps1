# KSC Threat Response Script copy write John Morgan 2017.
# This script is distributed using GPLv3 License.
# https://www.gnu.org/licenses/gpl-3.0.en.html
# This script comes with no warranty either expressed or implied.
# This script is intended to be used/deployed by ProofPoint Threat Response
# and reports data back to PPTR to be used in incident response.  This script
# can be run directly from the PowerShell console if you wish.

Write-Output "Beginning Script..."
# Action taken is determined by the KSC naming scheme.  You will need to modify the script to
# take advantage of your organization's naming scheme, or key off of some other computer attribute.

#Attempt to delete any old tasks if they exist.
schtasks /delete /tn reboot /f
schtasks /delete /tn ksclockdown /f	

#Grab all errors from the event log for the last 30 minutes.
Write-Output "Gathering Log Data..."
Write-Output "Application Log"
Get-EventLog application -After (Get-Date).AddMinutes(-30) | Where-Object{$_.EntryType -ne 'Information' } | Format-Table -autosize -wrap -Property TimeGenerated,Message
Write-Output "System Log"
Get-EventLog system -After (Get-Date).AddMinutes(-30) | Where-Object{$_.EntryType -ne 'Information' } | Format-Table -autosize -wrap -Property TimeGenerated,Message
Write-Output "Preparing Response"

#Figure out when to reboot
$then = (get-date).AddMinutes(10).ToString("HH:mm")

# Our non-persistent VDI systems all begin with "VDI".  Reboot the system to return it to a known good state.
if( $env:ComputerName -like "VDI*"){
	Write-Output "VDI no unlock code generated - System Schedule for Reboot"
	#Schedule a shutdown
	schtasks /create /tn "reboot" /tr "shutdown -s -f -d P:5:19 -t 60" /ru system /sc once /st $then	
	# Old shutdown method was causing a race condition.
	#	&shutdown -r -f -c "DO NOT LOGOFF, SHUTDOWN, or REBOOT!`r`n`r`nThe system will automatically reboot in 5 minutes.`r`n`r`nSAVE YOUR WORK!`r`n`r`nKelsey-Seybold Information Security is investigating this system for malware.  You will be notified if any further action is necessary.`r`n`r`n" -d P:5:19 -t 300
# VM2 is the name given to all persistent VDI.  Shut these down.	
}elseif( $env:ComputerName -like "VM2*" ){
	Write-Output "Persistent no unlock code generated - System Shut Down"
	#Schedule a shutdown
	schtasks /create /tn "reboot" /tr "shutdown -s -f -d P:5:19 -t 60" /ru system /sc once /st $then
	# Old shutdown method was causing a race condition.	
	#	&shutdown -s -f -c "DO NOT LOGOFF, SHUTDOWN, or REBOOT!`r`n`r`nSAVE YOUR WORK!`r`n`r`nThe system will automatically shut down in 5 minutes.`r`n`r`nDO NOT restart without speaking to Information Security`r`n`r`nKelsey-Seybold Information Security is investigating this system for malware.  We will be attempting to call you shortly.  If you haven't heard from us within 10 minutes, call the Infosec On-Call Phone: 713-364-4636." -d P:5:19 -t 300
# KS1 and VM1 are servers.  do not impede their ability to work.	
}elseif( $env:ComputerName -like "VM1*" -or $env:ComputerName -like "KS1*" ){
	Write-Output "Server!  No action taken"
}else{
	# All other systems are physical workstations.  We will warn the
	# user, then place a pair of lock and unlock scripts on the device
	# and shut it down.
	
	# Generate the unlock code.
	# The four digit code is the minute and second the script ran.
	# This is not intended to be cryptographically sound, just
	# complex enough that the users can't memorize/share the code.
	$a = Get-Date -Format mmss
	$b = 'myCode=' + $a
	# Write the code to a text file named "key.txt"
	write-output $a > 'c:\temp\key.txt'
	# Send the unlock code to the Threat Response Console.
	Write-Output "Unlock Code: $a"
	#Create a script to lock and unlock the network ports on the system.
	#The first write creates the file.
	write-output "Create Lockdown Script..."
	write-output 'strComputer = "."' > 'c:\temp\lockdown.vbs'
	#All subsequent writes use the append >> operator.
	write-output 'Set obj = CreateObject("Scripting.FileSystemObject")' >> 'c:\temp\lockdown.vbs'
	#Disable Network Interfaces
	write-output 'Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\CIMV2")' >> 'c:\temp\lockdown.vbs'
	write-output 'Set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_NetworkAdapter Where NetEnabled = ''True''")' >> 'c:\temp\lockdown.vbs'
	write-output 'For Each objItem in colItems' >> 'c:\temp\lockdown.vbs'
	write-output '    objItem.Disable' >> 'c:\temp\lockdown.vbs'
	write-output 'Next' >> 'c:\temp\lockdown.vbs'
	#Monitor for existence of the "key.txt" file.
	write-output 'while obj.FileExists("c:\temp\key.txt")' >> 'c:\temp\lockdown.vbs'
	write-output 'wend' >> 'c:\temp\lockdown.vbs'
	#When the key file no longer exists, unlock the system.
	#The file will be deleted by the other VBScript that is
	#visible to the user.  This also makes it easy for desktop
	#to unlock the system without knowing the key by simply deleting
	#the c:\temp\key.txt file.
	#Enable Nework Interfaces
	write-output 'For Each objItem in colItems' >> 'c:\temp\lockdown.vbs'
	write-output '    objItem.Enable' >> 'c:\temp\lockdown.vbs'
	write-output 'Next' >> 'c:\temp\lockdown.vbs'
	#Remove the schedule task.
	write-output 'Set objShell = Wscript.CreateObject("Wscript.Shell")' >> 'c:\temp\lockdown.vbs'
	write-output 'objShell.Run("schtasks /delete /tn ""KSCLockDown"" /f")' >> 'c:\temp\lockdown.vbs'
	#Remove the VBScript files associated with the scheduled task.
	write-output 'obj.DeleteFile("c:\temp\lockdown.vbs")' >> 'c:\temp\lockdown.vbs'
	write-output 'obj.DeleteFile("C:\programdata\microsoft\windows\start menu\programs\startup\KSCUnlock.vbs")' >> 'c:\temp\lockdown.vbs'
	
	# Write a VBScript to allow the user to see a dialog box to unlock the computer.
	Write-Output "Writing Unlock Script..."
	$b='strCode="' + $a + '"'
	write-output $b > 'C:\programdata\microsoft\windows\start menu\programs\startup\KSCUnlock.vbs'
	write-output 'while NOT(strInput = strCode)' >> 'C:\programdata\microsoft\windows\start menu\programs\startup\KSCUnlock.vbs'
	write-output '    strInput = InputBox("This computer has been locked down due to suspected malware.  Enter the unlock code to restore normal operation.", "KSC Information Security")' >> 'C:\programdata\microsoft\windows\start menu\programs\startup\KSCUnlock.vbs'
	write-output 'wend' >> 'C:\programdata\microsoft\windows\start menu\programs\startup\KSCUnlock.vbs'
	write-output 'Set obj = CreateObject("Scripting.FileSystemObject")' >> 'C:\programdata\microsoft\windows\start menu\programs\startup\KSCUnlock.vbs'
	write-output 'obj.DeleteFile("C:\temp\key.txt")' >> 'C:\programdata\microsoft\windows\start menu\programs\startup\KSCUnlock.vbs'

	# Create the task pointing to the script written above.
	# Needed to move this below all file creation to get around a bug in PowerShell v1 & v2. Described below
	# http://www.leeholmes.com/blog/2008/07/30/workaround-the-os-handles-position-is-not-what-filestream-expected/
	schtasks /create /tn "KSCLockDown" /tr "c:\Windows\SysWOW64\cscript.exe c:\temp\lockdown.vbs" /ru system /sc ONSTART
	#Schedule a shutdown
	schtasks /create /tn "reboot" /tr "shutdown -s -f -d P:5:19 -t 60" /ru system /sc once /st $then
	# Old shutdown method was causing a race condition.
	#&shutdown -s -f -c "DO NOT LOGOFF, SHUTDOWN, or REBOOT!`r`n`r`nThe system will automatically shut down in 5 minutes.`r`n`r`nSAVE YOUR WORK!`r`n`r`nKelsey-Seybold Information Security is investigating this system for malware.  We will be attempting to call you shortly.  If you haven't heard from us within 10 minutes, call the Information Security On-Call Number: 713-364-4636." -d P:5:19 -t 300
}
Write-Output "Script Complete..."
exit 0