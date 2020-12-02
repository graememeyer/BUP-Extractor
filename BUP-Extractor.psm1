<#
.SYNOPSIS
    Extracts and decodes files that have been quarantined by McAfee Anti-Virus from their .BUP containers.
.DESCRIPTION
    This PowerShell module extracts and decodes files that have been quarantined by McAfee Anti-Virus from their .BUP containers.

    McAfee quarantines files first by encoding them using a bitwise XOR operation and the key "6A" (0x006a as a byte or 106 as a decimal).
    Details of the qurantined file are stored in a text file, which is encoded with the same key. 
    Both files (the quarantined file + the details file) are then combined in "Compound File Binary Format" file. AKA, "COM Structured Storage" or "OLE file".

    This PowerShell module uses a 7-zip to extract the details and quarantined files, and a bespoke, compiled C DLL to quickly decode them in-place.

.EXAMPLE
    # Extract a BUP file
    Sample Files> Expand-BUPFile .\7e49612f3a3030.bup

    Expanding the BUP archive...
    Decoding the BUP details file...
    The BUP archive 7e49612f3a3030 contains "C:\Windows\mssecsvc.exe", which was detected as "Generic.ayx"
    Decoding the BUP qurantined file...
    The quarantined file was decoded and extracted to .\Sample Files\7e49612f3a3030\File_0
    Sample Files>  


    A simple demonstration of extracting the quarantined file.

    .EXAMPLE
    # Extract just the details from a BUP archive
    Sample Files> Expand-BUPFile .\7e496101d35960.bup -InfoOnly

    Extracting the BUP details file...
    Decoding the BUP details file...
    The BUP archive 7e496101d35960 contains "C:\Windows\mssecsvc.exe", which was detected as "Generic.ayx"
    The details file was decoded and extracted to .\Sample Files\7e496101d35960\Details
    Sample Files>


    A simple demonstration of how to extract the "details" file from the container, without extracting the potentially malicious quarantined file.
.INPUTS
    [System.IO.FileInfo] $InputBUPFile,
    [String] $OutputDirectory,
    [Switch] $InfoOnly
.OUTPUTS
    Output (if any)
.NOTES
    Due to the nature of quarantined files, you are quite likely to extract and decode malicious files, which your anti-virus software may have a problem with.

    Most AV programs will let you exclude a directory from AV scanning/alerting, which should give you somewhere safe to extract the quarantined files to.

    BUP-Extractor also includes an "-InfoOnly" switch which will only extract and decode the "details" file and may be able to meet your needs without triggering your AV.
.LINK
    # Project repository
    https://github.com/graememeyer/BUP-Extractor

    # McAfee Knowledge Center: How to restore a quarantined file not listed in the Quarantine Manager
    https://kc.mcafee.com/corporate/index?page=content&id=KB72755&actp=null&viewlocale=en_US&showDraft=false&locale=en_US

    # Wikipedia: Compound File Binary Format
    https://en.wikipedia.org/wiki/Compound_File_Binary_Format

    # SANS ISC: Analyzing Quarantine Files
    https://isc.sans.edu/forums/diary/Analyzing+Quarantine+Files/19867/
#>

function Expand-BUPFile {
    [alias("Expand-BUPContent")]
    [alias("Expand-BUPContents")]
    [alias("Expand-BUPArchive")]
    param(
        [Parameter(mandatory=$True)] [Alias("Path", "Input")] [ValidateScript({
            if( -Not ($_ | Test-Path) ) { throw "File of folder does not exist" }
            return $True
        })]
        [System.IO.FileInfo] $InputBUPFile,

        [Parameter(mandatory=$False)] [Alias("Output", "OutputPath")] [ValidateScript({
            if( -not ($_ | Test-Path -PathType "container") ){ throw "Not a valid output directory" }
            return $True            
        })]
        [String] $OutputDirectory = (Get-Item $InputBUPFile).Directory.FullName,

        [Switch] $InfoOnly
    )
    process {
        $ModuleDirectory = (Get-Module "BUP-Extractor").Path | Split-Path -Parent
        $7zPath = Get-ChildItem "$ModuleDirectory\bin\7z.exe" | Select-Object -ExpandProperty "FullName"
        $FileName = [System.IO.Path]::GetFileNameWithoutExtension($InputBUPFile)
        $BUPOutputDirectory = Join-Path -Path $OutputDirectory -ChildPath $FileName

        if ($InfoOnly) {
            Write-Host "Extracting the BUP details file..."
            $ArgumentList = "e `"$InputBUPFile`" -o`"$BUPOutputDirectory`" -aoa -r `"Details`""
        }
        else {
            Write-Host "Expanding the BUP archive..."
            $ArgumentList = "e `"$InputBUPFile`" -o`"$BUPOutputDirectory`" -aoa"
        }
        
        Start-Process -FilePath $7zPath -ArgumentList $ArgumentList -Wait

        $DetailsPath = Join-Path -Path $BUPOutputDirectory -ChildPath "Details"
        $File_0Path = Join-Path -Path $BUPOutputDirectory -ChildPath "File_0"

        Write-Host "Decoding the BUP details file..."
        Unprotect-BxorEncodedFile $DetailsPath
        $BUPDetails = $DetailsPath | Get-BUPFileDetails
        Write-Host "The BUP archive $FileName contains `"$($BUPDetails.File_0.OriginalName)`", which was detected as `"$($BUPDetails.Details.DetectionName)`""
        Write-Host "The details file was decoded and extracted to $DetailsPath"
        if ($Info) {
            Return $BUPDetails
        }
        if (-not $InfoOnly) {
            Write-Host "Decoding the BUP qurantined file..."
            Unprotect-BxorEncodedFile $File_0Path
            Write-Host "The quarantined file was decoded and extracted to $File_0Path"
        }
    }
}

function Protect-BupFile {
    [alias("Unprotect-BupFile")]
    [alias("Encode-BupFile")]
    [alias("Decode-BupFile")]
    [alias("Protect-BxorEncodedFile")]
    [alias("Unprotect-BxorEncodedFile")]
    [alias("Bxor-File")]
    [alias("BxorEncode-File")]
    [alias("BxorDecode-File")]

    [CmdletBinding()]
    param(
        [Parameter(mandatory=$True, ValueFromPipeline=$True)] [ValidateScript({
            if( -Not ($_ | Test-Path) ) { throw "Invalid input file - it may not exist" }
            return $True
        })]
        [System.IO.FileInfo] $InputFile,

        [Parameter(mandatory=$False)] [String] $OutputFile,
        [Parameter(mandatory=$False)] [Char] $Key = [Char]0x006A
    )
    process {
        $FileNameWithoutExtension = [System.IO.Path]::GetFileNameWithoutExtension($InputFile)
        $OutputDirectory = (Get-Item $InputFile).Directory.FullName
        if(-Not $OutputFile) {
            $OutputFile = (Join-Path -Path $OutputDirectory -ChildPath $FileNameWithoutExtension)
        }

        $OutputResult = Get-Content $InputFile -ReadCount 0 -Encoding Byte | Unprotect-Bytes -Key "0x006A" 
        
        Set-Content -Path $OutputFile -Value $OutputResult -Encoding Byte -Force
    }
}

function Protect-Bytes {
    [alias("Unprotect-Bytes")]
    [alias("BxorEncode-Bytes")]
    [alias("BxorDecode-Bytes")]
    [alias("Encode-BytesWithBxor")]
    [alias("Decode-BytesWithBxor")]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)] [Byte[]] $InputByteArray,
        [Parameter(mandatory=$False)] [Byte] $Key = [Byte]0x006A
    )
    process {
        if("BXORClass" -as [Type]) {
            
        }
        else {
            $SourceCode = @"
            using System;
            using System.Runtime.InteropServices;

            public class BXORClass
            {
                [DllImport("BXOR-DLL.dll")]
                public static extern void BXORBytes(
                    [Out] byte[] byteArray,
                    int len,
                    byte key
                );
            }
"@
            $ModuleDirectory = (Get-Module "BUP-Extractor").Path | Split-Path -Parent

            $DLLPath = Join-Path $ModuleDirectory -ChildPath '\bin\BXOR-DLL.dll'
            $DLLPath = $DLLPath -replace '\\', '\\'
            $Sourcecode = $Sourcecode -replace "BXOR-DLL.dll", $DLLPath
            Add-Type -TypeDefinition $SourceCode
        }

        $OutputByteArray = $InputByteArray
        [BXORClass]::BXORBytes($OutputByteArray, $OutputByteArray.Length, $Key)

        return $OutputByteArray
    }
}

function Get-BUPFileInfo {
    [alias("Get-QuarantineFileInfo")]
    [alias("Get-QuarantinedFileInfo")]
    [alias("Get-BUPFileDetails")]
    [alias("Get-QuarantineFileDetails")]
    [CmdletBinding()]
    param(
        [Parameter(mandatory=$True, ValueFromPipeline=$True)] [ValidateScript({
            if( -Not ($_ | Test-Path) ) { throw "Invalid input file - it may not exist" }
            return $True
        })]
        [System.IO.FileInfo] $InputFilePath
    )
    begin {
        if ($InputFilePath.Extension -match ".bup") {
            Expand-BUPFile -InputBUPFile $InputFilePath -InfoOnly
        }
    }
    process {
        $BUPDetailsObject = New-Object PSObject
        $DetailsFile = Get-Content $InputFilePath -ReadCount 0

        for ($i=0; $i -lt $DetailsFile.Length; $i++) {
            if (($DetailsFile[$i] -match "\[(?<CurrentStanza>\w+)\]") -or $i -eq $DetailsFile.Length -1) {
                if ($CurrentStanzaObject) {
                    $BUPDetailsObject | Add-Member -MemberType NoteProperty `
                                            -Name $CurrentStanza `
                                            -Value $CurrentStanzaObject
                }
                $CurrentStanzaObject = New-Object PSObject
                $CurrentStanza = $Matches.CurrentStanza
            }
            elseif($DetailsFile[$i] -match "^(?<Key>\w+)=(?<keyvalue>.*$)") {
                $CurrentStanzaObject | Add-Member -MemberType NoteProperty  `
                                                    -Name $Matches.key `
                                                    -Value $Matches.keyvalue
            }
        }
        return $BUPDetailsObject
    }
}