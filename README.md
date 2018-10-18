# LockDown
Works with ProofPoint Threat Response to disable infected computers.
Our current production version of Threat Response is v4.2.0.

The purpose of this script is to prevent infected computers from
spreading infection on the network.  We have several types of
systems, and each must be treated differently.

<h2>SERVERS</h2>
Must not be automatically disabled.

<h2>NONPERSISTENT VDI</h2>
A reboot or shutdown will elminate most
threats as these systems return to a
"golden image" each time they are started.

<h2>PERSISTENT VDI</h2>
We shut these systems down.  If the
Analyst determines that the systems
are not infected, they can simply be
restarted.  If the system is infected;
it will be restored to a prevsious
known good state.

<h2>PHYSICAL WORKSTATIONS</h2>
We schedule a startup task that disables
all of the network interfaces, then
schedule a second task to reboot the
machine.  There is a 2nd script written
to the STARTUP folder in the programs
menu that gives the user a chance to
"unlock" the computer by entering a
four digit code.

We are shutting down the computers via a scheduled task becasue
doing to by simply enterin the shutdown command was causing a
race condition with Threat Response.  As of this writing, 
collections are taking 2-6 minutes, and the reboot is set to
occur 10 minutes after the script starts running.

<h2>Summary</h2>
While I don't expect this script to be useful "as is" to anyone
outside of the organization, it may prove useful with some slight
tweeks.  Failing that, feel free to use this code to write your
own solution.
