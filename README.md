# BUP-Extractor
A PowerShell module to extract files that have been quarantined by McAfee Anti-Virus from their .bup containers.

# Installation - Automatic /  PowerShell Gallery

You can now install BUP-Extractor straight from the PowerShell Gallery just by running:

``` PowerShell
Install-Module BUP-Extractor
```

If you get a message about needing a newer NuGet provider version, install that as recommended. You will likely also need to accept the warning about trusting the PSReporitory. 

# Installation - Manual

Download the module as a ZIP from this GitHub repository to your user's PSModulePath. You can check the location of your PSModulePath as follows:

``` PowerShell
PS C:\> $ENV:PSModulePath
C:\Users\username\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
```

In this case, the user's PSModulePath is located at `C:\Users\username\Documents\WindowsPowerShell\Modules`, so create a child folder structure as follows: `C:\Users\username\Documents\WindowsPowerShell\Modules\BUP-Extractor\1.0.1\`. Note that the folder for this module [should be called](https://docs.microsoft.com/en-us/powershell/scripting/developer/module/installing-a-powershell-module?view=powershell-5.1#use-the-correct-module-directory-name) `BUP-Extractor`, not `BUP-Extractor-main` or anything like that, as GitHub seems to be providing now.

The end result should look something like this:

``` PowerShell
Get-ChildItem .

Directory: C:\Users\username\Documents\WindowsPowerShell\Modules\BUP-Extractor\1.0.1

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        12/5/2020   2:02 PM                bin
-a----        12/5/2020   2:00 PM           8856 BUP-Extractor.psd1
-a----        12/2/2020   9:26 PM           9946 BUP-Extractor.psm1
-a----        12/2/2020   9:33 PM           2333 LICENSE
-a----        12/2/2020   9:36 PM           1990 README.md
```

Import the module: 
``` PowerShell
Import-Module .\BUP-Extractor.psd1
```

# Usage

View the capabilities:
``` PowerShell
Sample Files> Get-Command -Module BUP-Extractor

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Expand-BUPFile                                     1.0.1      BUP-Extractor
Function        Get-BUPFileInfo                                    1.0.1      BUP-Extractor
Function        Protect-BupFile                                    1.0.1      BUP-Extractor
Function        Protect-Bytes                                      1.0.1      BUP-Extractor
```

Extract a BUP file:
``` PowerShell
Sample Files> Expand-BUPFile .\7e49612f3a3030.bup

Expanding the BUP archive...
Decoding the BUP details file...
The BUP archive 7e49612f3a3030 contains "C:\Windows\mssecsvc.exe", which was detected as "Generic.ayx"
Decoding the BUP qurantined file...
The quarantined file was decoded and extracted to .\Sample Files\7e49612f3a3030\File_0
```

Extract just the details from a BUP archive
``` PowerShell
Sample Files> Expand-BUPFile .\7e496101d35960.bup -InfoOnly

Extracting the BUP details file...
Decoding the BUP details file...
The BUP archive 7e496101d35960 contains "C:\Windows\mssecsvc.exe", which was detected as "Generic.ayx"
The details file was decoded and extracted to .\Sample Files\7e496101d35960\Details
```

# License

This project is distrubuted under the MIT license, with the exception of the included 7-Zip executable
which is distributed under the LGPL License, as per the 7-Zip "License for use and distribution" notice.

Please see the LICENSE file for more information.