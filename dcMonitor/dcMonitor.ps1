<#
.SYNOPSIS
Compares DSC Configurations from multiple Azure Automation Accounts to code stored in a gitHub repositiory V7.0

.DESCRIPTION
Compares DSC Configurations from multiple Azure Automation Accounts to code stored in a gitHub repositiory.  If the code is newer in the repo,
the gitHub action deploys and compiles the new code to a given automation account.

.PARAMETER ComputerName
The description of a parameter. Add a .PARAMETER keyword for each parameter in the function or
script syntax.

Type the parameter name on the same line as the .PARAMETER keyword. Type the parameter description
on the lines following the .PARAMETER keyword. Windows PowerShell interprets all text between the
.PARAMETER line and the next keyword or the end of the comment block as part of the parameter
description. The description can include paragraph breaks.

The Parameter keywords can appear in any order in the comment block, but the function or script
syntax determines the order in which the parameters (and their descriptions) appear in help topic.
To change the order, change the syntax.

.EXAMPLE
dcMonitor -ComputerName localhost

A sample command that uses the function or script, optionally followed by sample output and a
description. Repeat this keyword for each example. PowerShell automatically prefaces the first line
with a PowerShell prompt. Additional lines are treated as output and description. The example can
contain spaces, newlines and PowerShell code.

If you have multiple examples, there is no need to number them. PowerShell will number the examples in help text.

.EXAMPLE
dcMonitor -FilePath "C:\output.txt"

This example will be labeled "EXAMPLE 2" when help is displayed to the user.
#>
configuration dcMonitor
{
    param
    (
        [string]$ComputerName = 'localhost',
        # Provide a PARAMETER section for each parameter that your script or function accepts.
        [string]$FilePath = 'C:\Destination.txt'
    )

Node $ComputerName
    {
        File HelloWorld
        {
            Contents="Hello World"
            DestinationPath = $FilePath
        }
    }
} #End Configuration dcMonitor