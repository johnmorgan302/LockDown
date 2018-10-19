# ====[ KSC LockDown Script for use with ProofPoint Threat Response ]===== 
# Copyright John Morgan 2017,2018.
# This script comes with no warranty either expressed or implied.
#
# This script is distributed using GPLv3 License 
# https://www.gnu.org/licenses/gpl-3.0.en.html
# In order to get documentation and the lastest 
# version of the script, referenc the GIT repository 
# https://github.com/johnmorgan302/LockDown 


#=[ VARIABLES ]===========================================================

# REBOOT TIME - Don't reboot the workstation until it has had time to 
#               report data back to Threat Response.
$rebootDelay = 10 #Minutes
$rebootStatus = "Reboot Delay = " + $rebootDelay + " minutes"
Write-Output $rebootStatus 
$rebootTime = (get-date).AddMinutes($rebootDelay).ToString("HH:mm")

# UNLOCK CODE - We need a code complex enough that users can't guess it,
#               but simple enough that they can type it.  We use the
#               minute and second the event script started running
#               formatted as a four digit number.
#               $a = Get-Date -Format mmss
#
#               If you want a static code, you can simple set $a to
#               a value of your choosing.
#               $a = "1234"
$a = Get-Date -Format mmss
#              WARNING: The script seeks to write a file with this 
#              code into c:\temp.  If c:\temp doesn't exist on your 
#              machines, uncomment the line below.
#mkdir c:\temp

#=[ HOUSE KEEPING ]======================================================

# Report back to the console that things are getting under way.
Write-Output "Beginning Script."

#=[ HANDLE DIFFERENT SYSTEM TYPES]=======================================
# Our non-persistent VDI systems all begin with "VDI".  
# Reboot the system to return it to a known good state.
# I know we are calling this a reboot, but it's actually
# a shutdown.

if( $env:ComputerName -like "VDI*"){
	Write-Output "VDI no unlock code generated - System Schedule for Reboot"
	#Schedule a shutdown
	schtasks /create /tn "kscreboot" /tr "shutdown -s -f -d P:5:19 -t 60" /ru system /sc once /st $rebootTime	
# VM2 is the name given to all persistent VDI.  Shut these down.	
}elseif( $env:ComputerName -like "VM2*" ){
	Write-Output "Persistent no unlock code generated - System Shut Down"
	#Schedule a shutdown
	schtasks /create /tn "kscreboot" /tr "shutdown -s -f -d P:5:19 -t 60" /ru system /sc once /st $rebootTime
# KS1 and VM1 are servers.  TAKE NO ACTION!
}elseif( $env:ComputerName -like "VM1*" -or $env:ComputerName -like "KS1*" ){
	# Our analysts should be sharp enough to know this,
	# but spelling it out never hurts.
	Write-Output "Server!  No action taken!"
}else{
	# All other system names are physical workstations.  We will warn the
	# We will schedule a reboot job (shutdown), and schedule a second
	# job to disable all network interfaces when the system restarts.
	
	# The key code is determined in the variables section at the top of
	# the script and is called $a.

	# Write the code to a text file named "key.txt"
	write-output $a > 'c:\temp\key.txt'
	# NOTE: If the line above failes, go back to the
	# VARIABLES section and uncomment the line to
	# Make the c:\temp directory.
	
	# Create a script to lock and unlock the network ports on the system.
	# The first write creates the file.  Subsequent lines are appended.
	# If the script is truncated, make sure that someone hasn't
	# accidentally replaced >> with >.
	write-output "Create Lockdown Script."
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
	#Remove the scheduled tasks.
	write-output 'Set objShell = Wscript.CreateObject("Wscript.Shell")' >> 'c:\temp\lockdown.vbs'
	write-output 'objShell.Run("schtasks /delete /tn ""ksclockdown"" /f")' >> 'c:\temp\lockdown.vbs'
	write-output 'objShell.Run("schtasks /delete /tn ""kscreboot"" /f")' >> 'c:\temp\lockdown.vbs'
	#Remove the VBScript files associated with the scheduled task.
	write-output 'obj.DeleteFile("c:\temp\lockdown.vbs")' >> 'c:\temp\lockdown.vbs'
	write-output 'obj.DeleteFile("C:\programdata\microsoft\windows\start menu\programs\startup\KSCUnlock.vbs")' >> 'c:\temp\lockdown.vbs'
	
	# Write a VBScript to allow the user to see a dialog box to unlock the computer.
	# In order to be seen the file must be in the STARTUP folder of the Program
	# Files menu. (C:\programdata\microsoft\windows\start menu\programs\startup\KSCUnlock.vbs)
	Write-Output "Writing Unlock Script."
	$myString =  "Unlock Code = " + $a
	Write-Output $myString
	$b='strCode="' + $a + '"'
	write-output $b > 'C:\programdata\microsoft\windows\start menu\programs\startup\kscunlock.vbs'
	write-output 'while NOT(strInput = strCode)' >> 'C:\programdata\microsoft\windows\start menu\programs\startup\kscunlock.vbs'
	write-output '    strInput = InputBox("This computer has been locked down due to suspected malware.  Enter the unlock code to restore normal operation.", "KSC Information Security")' >> 'C:\programdata\microsoft\windows\start menu\programs\startup\kscunlock.vbs'
	write-output 'wend' >> 'C:\programdata\microsoft\windows\start menu\programs\startup\kscunlock.vbs'
	write-output 'Set obj = CreateObject("Scripting.FileSystemObject")' >> 'C:\programdata\microsoft\windows\start menu\programs\startup\kscunlock.vbs'
	write-output 'obj.DeleteFile("C:\temp\key.txt")' >> 'C:\programdata\microsoft\windows\start menu\programs\startup\kscunlock.vbs'

	# Create the task pointing to the script written above.
	# Needed to move this below all file creation to get around a bug in PowerShell v1 & v2. Described below
	# http://www.leeholmes.com/blog/2008/07/30/workaround-the-os-handles-position-is-not-what-filestream-expected/
	schtasks /create /tn "ksclockdown" /tr "c:\Windows\SysWOW64\cscript.exe c:\temp\lockdown.vbs" /ru system /sc ONSTART
	#Schedule a shutdown
	schtasks /create /tn "kscreboot" /tr "shutdown -s -f -d P:5:19 -t 60" /ru system /sc once /st $rebootTime
}

# Grab all errors from the Application and System Event logs for the last 30 minutes.
# And output them to the ProofPoint Threat Response console.
Write-Output "Gathering Log Data (Only severity greater than Information will be shown)."
Write-Output "Application Log"
Get-EventLog application -After (Get-Date).AddMinutes(-30) | Where-Object{$_.EntryType -ne 'Information' } | Format-Table -autosize -wrap -Property TimeGenerated,Message
Write-Output "System Log"
Get-EventLog system -After (Get-Date).AddMinutes(-30) | Where-Object{$_.EntryType -ne 'Information' } | Format-Table -autosize -wrap -Property TimeGenerated,Message

# Nofity the Analyst that the script has completed.
Write-Output "Script Complete."
exit 0