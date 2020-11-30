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
                [DllImport(".\\bin\\BXOR-DLL.dll")]
                public static extern void BXORBytes(
                    [Out] byte[] byteArray,
                    int len,
                    byte key
                );
            }
"@
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