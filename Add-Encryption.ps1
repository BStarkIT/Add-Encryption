function add-encyrption {
<#
.SYNOPSIS
    This script is part of the BStarkIT PowerShell module collection.
    It is designed to encrypt a password and save it to a specified file in the user's .ssh directory.
    Ensure that the AES key file exists in the .ssh directory before running this script.
    The script checks if the specified file already exists and prompts the user to choose a different file name if it does.
    The script also checks if the AES key file exists and prompts the user if it does not.
    The script uses the ConvertTo-SecureString and ConvertFrom-SecureString cmdlets to encrypt the password.
    The encrypted password is saved to the specified file in the user's .ssh directory.
.DESCRIPTION
    A Script to encrypt a password and save it to a file.
.NOTES
    Script written by: Brian Stark
    Date: 02/06/2025
    Modified by:
    Date:
    Version: 1.0
.COMPONENT
    PowerShell Version 5
.PARAMETER Text
    encrypted password text to save
.PARAMETER File
    file name to save the encrypted password
.PARAMETER Key
    AES key file to use for encryption
.PARAMETER EncryptedFile
    file to save the encrypted password
.INPUTS
    Text and File parameters are mandatory inputs.
    The Text parameter is the password to encrypt, and the File parameter is the name of the file to save the encrypted password.
.OUTPUTS
    The script outputs a message indicating whether the password has been successfully encrypted and saved to the specified file.
.EXAMPLE
# add-encyrption -Text "MySecretPassword" -File "myEncryptedPassword.txt"
    This command encrypts the password "MySecretPassword" and saves it to the file "myEncryptedPassword.txt" in the user's .ssh directory.
.LINK
    Scripts can be found at: https://github.com/BStarkIT
#>
[CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $Text,
        [string] $File
    )

$Path = "$env:UserProfile\.ssh\"
$EncryptedFile = $Path + $File
if (!(Test-Path -Path $Path)) {
    New-Item -ItemType Directory -Path $Path -Force
}
# Check if the file already exists 
if (Test-Path -Path $EncryptedFile) {
    Write-Host "File already exists. Please choose a different file name."
    return
}
# Encrypt the password  
$ClearText = $Text
if ($ClearText -eq $null -or $ClearText -eq "") {
    Write-Host "No password provided. Exiting."
    return
}
# Load the AES key from a file
$KeyFile = "$env:UserProfile\.ssh\AES.key"
if (!(Test-Path -Path $KeyFile)) {
    Write-Host "Key file not found. Please ensure the AES.key file exists in the .ssh directory."
    return
}
# Read the key from the file and encrypt the password 
$Encryptionkey = Get-Content $KeyFile
$ClearText = ConvertTo-SecureString $ClearText -AsPlainText -Force
$EncryptedText = ConvertFrom-SecureString $ClearText -key $Encryptionkey 
Set-Content -Path $EncryptedFile -Value $EncryptedText
$EncryptedText = $null
$ClearText = $null
# Notify the user that the password has been encrypted and saved
Write-Host "Password has been encrypted and saved to $EncryptedFile"
    return
}
