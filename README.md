# BUP-Extractor
A PowerShell module to extract files that have been quarantined by McAfee Anti-Virus from their .bup containers.

# Installation

Import the module
``` PowerShell
Import-Module .\BUP-Extractor.psm1
```

View the capabilities:
``` PowerShell
Sample Files> Get-Command -Module BUP-Extractor

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Expand-BUPFile                                     1.0        BUP-Extractor
Function        Get-BUPFileInfo                                    1.0        BUP-Extractor
Function        Protect-BupFile                                    1.0        BUP-Extractor
Function        Protect-Bytes                                      1.0        BUP-Extractor

Sample Files>
```

# Usage

``` PowerShell
# Extract a BUP file
Sample Files> Expand-BUPFile .\7e49612f3a3030.bup

Expanding the BUP archive...
Decoding the BUP details file...
The BUP archive 7e49612f3a3030 contains "C:\Windows\mssecsvc.exe", which was detected as "Generic.ayx"
Decoding the BUP qurantined file...
The quarantined file was decoded and extracted to .\Sample Files\7e49612f3a3030\File_0
Sample Files>  
```


``` PowerShell
# Extract just the details from a BUP archive
Sample Files> Expand-BUPFile .\7e496101d35960.bup -InfoOnly

Extracting the BUP details file...
Decoding the BUP details file...
The BUP archive 7e496101d35960 contains "C:\Windows\mssecsvc.exe", which was detected as "Generic.ayx"
The details file was decoded and extracted to .\Sample Files\7e496101d35960\Details
Sample Files>
```

# License

