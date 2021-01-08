git clone -q https://github.com/PowerShell/DscResource.Tests

Import-Module -Name "$env:APPVEYOR_BUILD_FOLDER\DscResource.Tests\AppVeyor.psm1"
Invoke-AppveyorInstallTask

$ModuleManifest = Test-ModuleManifest .\$($env:RepoName).psd1 -ErrorAction SilentlyContinue
$repoRequiredModules = $ModuleManifest.RequiredModules.Name

[string[]]$PowerShellModules = @('posh-git', 'PSScriptAnalyzer')

if ($repoRequiredModules) { $PowerShellModules += $repoRequiredModules }

# Install the PowerShell Modules
Install-Module Pester -RequiredVersion '4.9.0' -Force -Confirm:$false -SkipPublisherCheck -AllowClobber -Repository PSGallery

ForEach ($Module in $PowerShellModules) {
    If (!(Get-Module -ListAvailable $Module -ErrorAction SilentlyContinue)) {
        Install-Module $Module -Scope CurrentUser -Force -Repository PSGallery
    }
    
    Import-Module $Module
}

Get-Module Pester -ListAvailable
Import-Module -Name Pester -RequiredVersion '4.9.0' -Force