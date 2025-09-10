function read-encyrption {
    <#
.SYNOPSIS 
Script to read and decrypt a password from an encrypted file.
.DESCRIPTION
A Script to read and decrypt a password from an encrypted file.
.NOTES
Script written by: Brian Stark
Date: 02/06/2025
Modified by:
Date:
Version: 1.0
.COMPONENT
PowerShell Version 5
PSModule: PS-Menu\PS-Menu.psm1
PSModule: Add-Encyrption\Add-Encyrption.psm1
PSModule: Read-Encyrption\Read-Encyrption.psm1
.REQUIREMENTS
    This script requires PowerShell 5.0 or later.
    It also requires the PS-Menu and Add-Encyrption modules to be installed.
    The script expects an AES key file named "AES.key" to be present in the user's .ssh directory.
    The encrypted password file should be in the same directory or specified by the user.
    The script uses the `set-Clipboard` cmdlet to copy the decrypted password to the clipboard.
    Ensure that the PS-Menu module is imported before running this script.
.LINK
All required modules can be found at
    https://github.com/BStarkIT/PSModules
.PARAMETER EncryptedFile
    The path to the encrypted file containing the password.
.INPUTS
    The EncryptedFile parameter is not mandatory, if no file is named, a menu of files is displayed.
.OUTPUTS
    The script outputs a message indicating whether the password has been successfully decrypted and copied to the clipboard.
.EXAMPLE
# read-encyrption -EncryptedFile "myEncryptedPassword.txt"
    This command reads the encrypted password from the file "myEncryptedPassword.txt" in the user's .ssh directory, decrypts it, and copies it to the clipboard.
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string] $EncryptedFile
    )
    # Load the AES key from a file
    $Encryptionkey = Get-Content "$env:UserProfile\.ssh\AES.key"
    if (-not $Encryptionkey) {
        Write-Host "Key file not found. Please ensure the AES.key file exists in the .ssh directory."
        return
    }
    if ($null -eq $EncryptedFile) {
        # If no file is specified, prompt the user to select one
        $menu = @()
        $menu += Get-ChildItem -Path "$env:UserProfile\.ssh" -File
        $EncryptedFile = menu ($menu)
    }
    $Encrypted = Get-Content $EncryptedFile
    if ($null -eq $Encrypted) {
        Write-Host "No content found in the encrypted file. Please check the file."
        return
    }
    # Decrypt the password
    $secureStringDecrypt = ConvertTo-SecureString $encrypted -Key $Encryptionkey
    if ($null -eq $secureStringDecrypt) {
        Write-Host "Decryption failed. Please check the key and the encrypted file."
        return
    }
    $secureStringToBSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureStringDecrypt)
    if ($secureStringToBSTR -eq [IntPtr]::Zero) {
        Write-Host "Decryption failed. Please check the key and the encrypted file."
        return
    }
    $stringDecrypted = [Runtime.InteropServices.Marshal]::PtrToStringAuto($secureStringToBSTR)
    if ($stringDecrypted -eq $null) {
        Write-Host "Decryption failed. Please check the key and the encrypted file."
        return
    }
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secureStringToBSTR)
    # Copy the decrypted password to the clipboard
    set-Clipboard -Value $stringDecrypted
    # Clear the secure string variable
    $secureStringDecrypt = $null
    $stringDecrypted = $null
    $Encryptionkey = $null
    # Notify the user
    Write-Host "Password has been decrypted and copied to clipboard."
    return
}
    
