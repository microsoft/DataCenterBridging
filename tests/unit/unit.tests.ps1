$DataFile   = Import-PowerShellDataFile ".\$($env:APPVEYOR_BUILD_FOLDER).psd1" -ErrorAction SilentlyContinue
$TestModule = Test-ModuleManifest       ".\$($env:APPVEYOR_BUILD_FOLDER).psd1" -ErrorAction SilentlyContinue

Describe "$($env:APPVEYOR_BUILD_FOLDER)-Manifest" {
    Context Validation {
        It "[Import-PowerShellDataFile] - $($env:APPVEYOR_BUILD_FOLDER).psd1 is a valid PowerShell Data File" {
            $DataFile | Should Not BeNullOrEmpty
        }

        It "[Test-ModuleManifest] - $($env:APPVEYOR_BUILD_FOLDER).psd1 should pass the basic test" {
            $TestModule | Should Not BeNullOrEmpty
        }
    }
}
