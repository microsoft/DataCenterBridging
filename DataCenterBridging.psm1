enum Ensure {
    Absent
    Present
}

[DscResource()]
Class DCBNetQosFlowControl {
    [DscProperty(Mandatory)]
    [Ensure] $Ensure

    [DscProperty(Key)]
    [ValidateRange(0,7)]
    [int] $Priority

    [DscProperty(NotConfigurable)]
    [Boolean] $Enabled

    [DCBNetQosFlowControl] Get() {
        $FlowControlPriority = Get-NetQosFlowControl -Priority $this.Priority

        $this.Enabled = $FlowControlPriority.Enabled
        $this.Priority = $FlowControlPriority.Priority

        return $this
    }

    [bool] Test() {
        $FlowControlPriority = Get-NetQosFlowControl -Priority $this.Priority

        $testState = $false
        if ($this.Ensure -eq [Ensure]::Present) {
            Switch ($FlowControlPriority.Enabled) {
                $true {$testState = $true}
                $false {$testState =  $false}
            }
        }
        elseif ($this.Ensure -eq [Ensure]::Absent) {
            Switch ($FlowControlPriority.Enabled) {
                $true {$testState =  $false}
                $false {$testState =  $true}
            } 
        }

        Return $testState
    }

    [Void] Set() {
        if ($this.Ensure -eq [Ensure]::Present) {
            Write-Verbose "Enabling priority $($this.Priority)"
            Set-NetQosFlowControl -Priority $this.Priority -Enabled $true
            Write-Verbose "Priority $($this.Priority) is now Enabled"
        }
        elseif ($this.Ensure -eq [Ensure]::Absent) {
            Write-Verbose "Enabling priority $($this.Priority)"
            Set-NetQosFlowControl -Priority $this.Priority -Enabled $false
            Write-Verbose "Priority $($this.Priority) is now disabled"
        }
    }
}

[DscResource()]
Class DCBNetAdapterQos {
    [DscProperty(Mandatory)]
    [Ensure] $Ensure

    [DscProperty(Key)]
    [string] $InterfaceName

    [DscProperty(NotConfigurable)]
    [Boolean] $Enabled

    [DCBNetAdapterQos] Get() {
        $NetAdapterQosState = Get-NetAdapterQos -Name $this.InterfaceName

        $this.InterfaceName = $NetAdapterQosState.Name
        $this.Enabled = $NetAdapterQosState.Enabled

        return $this
    }

    [bool]Test() {
        $NetAdapterQosState = Get-NetAdapterQos -Name $this.InterfaceName

        $testState = $false

        if ($this.Ensure -eq [Ensure]::Present) {
            Switch ($NetAdapterQosState.Enabled) {
                $true {$testState = $true}
                $false {$testState =  $false}
            }
        }
        elseif ($this.Ensure -eq [Ensure]::Absent) {
            Switch ($NetAdapterQosState.Enabled) {
                $true {$testState =  $false}
                $false {$testState =  $true}
            } 
        }

        Return $testState
    }

    [Void] Set() {
        if ($this.Ensure -eq [Ensure]::Present) {
            Write-Verbose "Enabling QoS on $($this.InterfaceName)"
            Set-NetAdapterQos -Name $this.InterfaceName -Enabled $true
            Write-Verbose "QoS is now enabled on $($this.InterfaceName)"
        }
        elseif ($this.Ensure -eq [Ensure]::Absent) {
            Write-Verbose "Disabling QoS on $($this.InterfaceName)"
            Set-NetAdapterQos -Name $this.InterfaceName -Enabled $false
            Write-Verbose "QoS is now disabled on $($this.InterfaceName)"
        }
    }
}

[DscResource()]
Class DCBNetQosDcbxSetting {
    [DscProperty(Key)]
    [Ensure] $Ensure

    [DCBNetQosDcbxSetting] Get() {
        $NetQosDcbx = Get-NetQosDcbxSetting

        if ($this.Ensure) {
            $this.Willing = $NetQosDcbx.Willing
        }

        return $this
    }

    [bool]Test() {
        $NetQosDcbx = Get-NetQosDcbxSetting

        $testState = $false

        if ($this.Ensure -eq [Ensure]::Present) {
            Switch ($NetQosDcbx.Willing) {
                $true {$testState = $true}
                $false {$testState =  $false}
            }
        }
        elseif ($this.Ensure -eq [Ensure]::Absent) {
            Switch ($NetQosDcbx.Willing) {
                $true {$testState =  $false}
                $false {$testState =  $true}
            } 
        }

        Return $testState
    }

    [Void] Set() {
        if ($this.Ensure -eq [Ensure]::Present) {
            Write-Verbose "Enabling DCBX Willing bit"
            Write-Verbose "Note: DCBX is not supported on Windows Server 2016 or Windows Server 2019"
            Set-NetQosDcbxSetting -Willing $true
            Write-Verbose "DCBX Willing bit is now enabled"
            Write-Verbose "Note: DCBX is not supported on Windows Server 2016 or Windows Server 2019"
        }
        elseif ($this.Ensure -eq [Ensure]::Absent) {
            Write-Verbose "Disabling DCBX Willing bit"
            Set-NetQosDcbxSetting -Willing $false
            Write-Verbose "DCBX Willing bit is now disabled"
        }
    }
}

[DscResource()]
Class DCBNetQosPolicy {
    [DscProperty(Mandatory)]
    [Ensure] $Ensure

    [DscProperty(Key)]
    [string] $Name

    [DscProperty(Mandatory)]
    [string] $PriorityValue8021Action

    [DscProperty()]
    [ValidateSet('Default', 'SMB', 'Cluster', 'LiveMigration')]
    [string] $Template

    [DscProperty()]
    [string] $NetDirectPortMatchCondition = 0

    [DCBNetQosPolicy] Get() {
        $NetQosPolicy = Get-NetQosPolicy -Name $this.Name -ErrorAction SilentlyContinue

        $this.Name = $NetQosPolicy.Name
        $this.PriorityValue8021Action = $NetQosPolicy.PriorityValue8021Action
        
        if ($NetQosPolicy.Template -ne 'None') { $this.Template = $NetQosPolicy.Template }
        
        if ($NetQosPolicy.NetDirectPortMatchCondition -ne '0') { 
            $this.NetDirectPortMatchCondition = $NetQosPolicy.NetDirectPortMatchCondition
        }

        return $this
    }

    [bool] Test() {
        $NetQosPolicy = Get-NetQosPolicy -Name $this.Name -ErrorAction SilentlyContinue

        $testState = $false

        If ($NetQosPolicy) {
            Switch ($this.Ensure) {
                'Present' {
                    $teststate = $true

                    If ($NetQosPolicy.PriorityValue8021Action -ne $this.PriorityValue8021Action) { $teststate = $false }

                    If ($this.Template) {
                        If ($NetQosPolicy.Template -ne $this.Template) { $teststate = $false }
                    }
                    
                    If ($this.NetDirectPortMatchCondition) {
                        If ($NetQosPolicy.NetDirectPortMatchCondition -ne $this.NetDirectPortMatchCondition) { $teststate = $false }
                    }
                }

                'Absent' { $teststate = $false }
            }
        } else {
            Switch ($this.Ensure) {
                'Present' { $teststate = $false }
                'Absent' { $teststate = $true }
            }
        }

        Return $testState
    }

    [Void] Set() {
        $NetQosPolicy = Get-NetQosPolicy -Name $this.Name -ErrorAction SilentlyContinue

        If ($NetQosPolicy) {
            Switch ($this.Ensure) {
                'Present' {
                    If ($this.PriorityValue8021Action) {
                        If ($NetQosPolicy.PriorityValue8021Action -ne $this.PriorityValue8021Action) {
                            Write-Verbose "Correcting the priority value of NetQosPolicy $($this.Name) to $($this.PriorityValue8021Action)"
                            Set-NetQosPolicy -Name $this.Name -PriorityValue8021Action $this.PriorityValue8021Action
                            Write-Verbose "Corrected the priority value of NetQosPolicy $($this.Name) to $($this.PriorityValue8021Action)"
                        }
                    }
                    
                    if ($this.NetDirectPortMatchCondition) {
                        If ($NetQosPolicy.NetDirectPortMatchCondition -ne $this.NetDirectPortMatchCondition) {
                            Write-Verbose "Correcting the NetDirectPortMatchCondition value of NetQosPolicy $($this.Name) to $($this.NetDirectPortMatchCondition)"
                            Set-NetQosPolicy -Name $this.Name -NetDirectPortMatchCondition $this.NetDirectPortMatchCondition
                            Write-Verbose "Corrected the NetDirectPortMatchCondition value of NetQosPolicy $($this.Name) to $($this.NetDirectPortMatchCondition)"
                        }
                    }

                    If ($this.Template) {
                        If ($NetQosPolicy.Template -ne $this.Template) {
                            Write-Verbose "Correcting the Template value of NetQosPolicy $($this.Name) to $($this.Template)"
                            $templateParam = @{ $this.Template = $true }
                            Set-NetQosPolicy -Name $this.Name @templateParam
                            Write-Verbose "Corrected the Template value of NetQosPolicy $($this.Name) to $($this.Template)"
                        }
                    }
                }

                'Absent' { 
                    Write-Verbose "Removing NetQosPolicy $($this.Name)"
                    Remove-NetQosPolicy -Name $this.Name
                    Write-Verbose "NetQosPolicy $($this.Name) has been removed"
                }
            }
        } else {
            if ($this.Ensure -eq [Ensure]::Present) {
                if ($this.NetDirectPortMatchCondition -ne 0) {
                    Write-Verbose "Creating NetQosPolicy $($this.Name)"
                    New-NetQosPolicy -Name $this.Name -PriorityValue8021Action $this.PriorityValue8021Action -NetDirectPortMatchCondition $this.NetDirectPortMatchCondition
                    Write-Verbose "NetQosPolicy $($this.Name) has been created"
                }
                elseif ($this.Template -ne 'None') {
                    Write-Verbose "Creating NetQosPolicy $($this.Name)"
                    $templateParam = @{ $this.Template = $true }
                    New-NetQosPolicy -Name $this.Name -PriorityValue8021Action $this.PriorityValue8021Action @templateParam
                    Write-Verbose "NetQosPolicy $($this.Name) has been created"
                }
                else { Write-Verbose 'Catastrophic Failure' }
            } 
        }
    }
}

[DscResource()]
Class DCBNetQosTrafficClass {
    [DscProperty(Mandatory)]
    [Ensure] $Ensure

    [DscProperty(Key)]
    [string] $Name

    [DscProperty(Mandatory)]
    [string] $Priority

    [DscProperty(Mandatory)]
    [ValidateRange(1,99)]
    [string] $BandwidthPercentage

    [DscProperty(Mandatory)]
    [ValidateSet('ETS','Strict')]
    [string] $Algorithm = 'ETS'

    [DCBNetQosTrafficClass] Get() {
        $NetQosTrafficClass = Get-NetQosTrafficClass -Name $this.Name -ErrorAction SilentlyContinue

        $this.Name = $NetQosTrafficClass.Name
        $this.Priority = $NetQosTrafficClass.Priority
        $this.BandwidthPercentage = $NetQosTrafficClass.BandwidthPercentage
        $this.Algorithm = $NetQosTrafficClass.Algorithm

        return $this
    }

    [bool] Test() {
        $NetQosTrafficClass = Get-NetQosTrafficClass -Name $this.Name -ErrorAction SilentlyContinue

        $testState = $false

        If ($NetQosTrafficClass) {
            Switch ($this.Ensure.ToString()) {
                'Present' {
                    $teststate = $true
                    If ($NetQosTrafficClass.Priority -ne $this.Priority) { $teststate = $false }
                    If ($NetQosTrafficClass.BandwidthPercentage -ne $this.BandwidthPercentage) { $teststate = $false }
                    If ($NetQosTrafficClass.Algorithm -ne $this.Algorithm) { $teststate = $false }
                }

                'Absent' { $teststate = $false }
            }
        } else {
            Switch ($this.Ensure) {
                'Present' { $teststate = $false }
                'Absent' { $teststate = $true }
            }
        }

        Return $testState
    }

    [Void] Set() {
        $NetQosTrafficClass = Get-NetQosTrafficClass -Name $this.Name -ErrorAction SilentlyContinue

        If ($NetQosTrafficClass) {
            Switch ($this.Ensure) {
                'Present' {
                    If ($NetQosTrafficClass.Priority -ne $this.Priority) {
                        Write-Verbose "Correcting the priority value of NetQosTrafficClass $($this.Name) to $($this.Priority)"
                        Set-NetQosTrafficClass -Name $this.Name -Priority $this.Priority
                        Write-Verbose "Corrected the priority value of NetQosTrafficClass $($this.Name) to $($this.Priority)"
                    }

                    If ($NetQosTrafficClass.BandwidthPercentage -ne $this.BandwidthPercentage) {
                        Write-Verbose "Correcting the BandwidthPercentage value of NetQosTrafficClass $($this.Name) to $($this.BandwidthPercentage)"
                        Set-NetQosTrafficClass -Name $this.Name -BandwidthPercentage $this.BandwidthPercentage
                        Write-Verbose "Corrected the BandwidthPercentage value of NetQosTrafficClass $($this.Name) to $($this.BandwidthPercentage)"
                    }

                    If ($NetQosTrafficClass.Algorithm -ne $this.Algorithm) {
                        Write-Verbose "Correcting the Algorithm value of NetQosTrafficClass $($this.Name) to $($this.Algorithm)"
                        Set-NetQosTrafficClass -Name $this.Name -Algorithm $this.Algorithm
                        Write-Verbose "Corrected the Template value of NetQosTrafficClass $($this.Name) to $($this.Algorithm)"
                    }
                }

                'Absent' { 
                    Write-Verbose "Removing NetQosTrafficClass $($this.Name)"
                    Remove-NetQosTrafficClass -Name $this.Name
                    Write-Verbose "NetQosTrafficClass $($this.Name) has been removed"
                }
            }
        } else {
            if ($this.Ensure -eq [Ensure]::Present) {
                Write-Verbose "Creating NetQosTrafficClass $($this.Name)"
                New-NetQosTrafficClass -Name $this.Name -Priority $this.Priority -BandwidthPercentage $this.BandwidthPercentage -Algorithm $this.Algorithm
                Write-Verbose "NetQosTrafficClass $($this.Name) has been created"
            } 
        }
    }
}

#region FabricInfo
#region Helper Functions (Not Exported)
Function Get-Interfaces {
    param (
        [Parameter(Mandatory=$false)]
        [String[]] $InterfaceNames,

        [Parameter(Mandatory=$false)]
        [String] $SwitchName
    )

    If ($SwitchName) {
        $VMSwitchTeam = Get-VMSwitchTeam -Name $SwitchName
        $Interfaces   = Get-NetAdapter -InterfaceDescription $VMSwitchTeam.NetAdapterInterfaceDescription
    }
    elseif ($InterfaceNames) { $Interfaces = Get-NetAdapter -Name $InterfaceNames }

    Return $Interfaces
}
#region LLDP
Function Invoke-BitShift {
    param (
        [Parameter(Mandatory,Position=0)]
        [int] $x ,

        [Parameter(ParameterSetName='Left')]
        [ValidateRange(0,[int]::MaxValue)]
        [int] $Left ,

        [Parameter(ParameterSetName='Right')]
        [ValidateRange(0,[int]::MaxValue)]
        [int] $Right
    )

    $shift = If($PSCmdlet.ParameterSetName -eq 'Left') { $Left }
            Else { -$Right }

    Return [math]::Floor($x * [math]::Pow(2,$shift))
}

Function Get-LLDPEvents {
    param ($RemainingIndexes)

    $EventPerInterface = @()
    :enoughEvents while ($remainingIndexes -ne $Null) {
        $CuratedEvents = Get-WinEvent -LogName Microsoft-Windows-LinkLayerDiscoveryProtocol/Diagnostic -Oldest -ErrorAction SilentlyContinue |
            Where-Object { $_.ID -eq 10041 -and $_.TimeCreated -ge (Get-Date).AddMinutes(-5)} | Sort-Object TimeCreated -Descending

        $CuratedEvents | ForEach-Object {
            $thisEvent = $_

            if ($remainingIndexes -contains $thisEvent.Properties[0].Value) {
                $remainingIndexes = $remainingIndexes | Where-Object { $_ -ne $thisEvent.Properties[0].Value }
                $EventPerInterface += $thisEvent
            }

            # Note: We only want one event per index, so we'll break here if we received enough events
            if ($remainingIndexes -eq $null) {break enoughEvents}
        }

        break enoughEvents
    }

    if ($RemainingIndexes -ne $Null) { $global:IndexesMissingEvents = $RemainingIndexes }

    return $EventPerInterface
}

Function Parse-LLDPPacket {
    param ($Events)

    $Table = @()

    $tlv = @{
        ChassisId            = 1
        PortId               = 2
        TimeToLive           = 3
        PortDescription      = 4
        SystemName           = 5
        OrganizationSpecific = 127
    }

    [Flags()] enum PFC_lower {
        Priority0 = 1
        Priority1 = 2
        Priority2 = 4
        Priority3 = 8
    }

    [Flags()] enum PFC_higher {
        Priority4 = 1
        Priority5 = 2
        Priority6 = 4
        Priority7 = 8
    }

    $Events | ForEach-Object {
        $thisEvent = $_
        $offset = 14
        $VLANID = @()
        $bytes = $thisEvent.Properties[3].Value

        $Destination = "{0:X2}:{1:X2}:{2:X2}:{3:X2}:{4:X2}:{5:X2}" -f $bytes[0..5]
        $SourceMac   = "{0:X2}:{1:X2}:{2:X2}:{3:X2}:{4:X2}:{5:X2}" -f $bytes[6..11]
        $EtherType   = "0x$([BitConverter]::ToString($bytes[12]) + [BitConverter]::ToString($bytes[13]))"

        While ($bytes[$offset] -ne 0) {
            $type   = $bytes[$Offset] -shr 1
            $Length = $Length = (Invoke-BitShift ($bytes[$offset] -band 1) -left 8) -bor $bytes[$offset + 1]

            Switch ($type) {
                $tlv.ChassisID {
                    Switch ($bytes[$offset + 2]) {
                        # Mac Address SubType
                        4 { $ChassisID = "{0:X2}:{1:X2}:{2:X2}:{3:X2}:{4:X2}:{5:X2}" -f $bytes[($offset + 3)..($offset + 8)] }
                    }
                }

                $tlv.PortDescription { $PortDescription = ([System.Text.Encoding]::ASCII.GetString($bytes[$Offset..($Offset + $Length + 1)])).Trim() }
                $tlv.SystemName      { $SystemName = ([System.Text.Encoding]::ASCII.GetString($bytes[$Offset..($Offset + $Length + 1)])).Trim()      }

                $tlv.OrganizationSpecific {
                    $OUI = [System.BitConverter]::ToString($bytes[($Offset+2)..($Offset + 4)]).Replace('-', ':')

                    Switch ($bytes[$offset + 5]) {
                        # Additional Subtypes - https://wiki.wireshark.org/LinkLayerDiscoveryProtocol#:~:text=All%20Organizationally%20Specific%20TLVs%20start%20with%20an%20LLDP,followed%20by%20a%201%20octet%20organizationally%20defined%20subtype
                        {$_ -eq '1' -and $OUI -eq '00:80:C2'} {
                            $NativeVLAN = (Invoke-BitShift $bytes[$offset + 6] -left 8) -bor $bytes[$offset + 7]
                        }
                        {$_ -eq '3' -and $OUI -eq '00:80:C2'} { $VLANID    += (Invoke-BitShift($bytes[$offset + 6] -band 0xf) -Right 8) -bor $bytes[$offset + 7] }
                        {$_ -eq '4' -and $OUI -eq '00:12:0f'} { $FrameSize  = (Invoke-BitShift $bytes[$offset + 6] -left 8) -bor $bytes[$offset + 7] }
                        {$_ -eq '11' -and $OUI -eq '00:80:C2'} {
                            # Possible that more than one is enabled, so need to grab all of these
                            # Uses exactly 1 byte to define the state of each PFC priority
                            #   The first 4 bits define upper range of priority e.g. 0001 = Priority 4 Enabled
                            #   The last 4 bits define lower range of priority e.g. 1000 = Priority 3 Enabled

                            $thisByte = "{0:D2}" -f $bytes[$offset + 7]
                            # HigherBits = the left-most values in the last byte; LowerBits = the right-most values in the last byte
                            $HigherBits = -join $thisByte.ToString()[0] # -join operates as a substring
                            $LowerBits  = -join $thisByte.ToString()[1] # -join operates as a substring

                            $PFC = @()
                            if ($HigherBits -ne 0) {
                                $HigherPriority = [enum]::GetValues([PFC_higher]) | Where-Object {$_.value__ -band $HigherBits}
                                foreach ($priority in $HigherPriority) { $PFC += $priority.toString() }
                            }

                            if ($LowerBits -ne 0)  {
                                $LowerPriority  = [enum]::GetValues([PFC_lower]) | Where-Object {$_.value__ -band $LowerBits}
                                foreach ($priority in $LowerPriority) { $PFC += $priority.toString() }
                            }
                        }
                    }
                }
            }

            $offset = $offset + $Length + 2
        }

        # Set defaults in case the switch doesn't provide the information and guide the customer in their troubleshooting
        if (-not($PortDescription)) { $PortDescription = 'Information Not Provided By Switch' }
        if (-not($SystemName)) { $SystemName = 'Information Not Provided By Switch' }
        if (-not($NativeVLAN)) { $NativeVLAN = 'Information Not Provided By Switch' }
        if (-not($VLANID))     { $VLANID = 'Information Not Provided By Switch' }
        if (-not($FrameSize))  { $FrameSize  = 'Information Not Provided By Switch' }
        if (-not($PFC)) { $PFC  = 'Information Not Provided By Switch' }

        $Table += [ordered] @{
            InterfaceName   = (Get-NetAdapter -InterfaceIndex $thisEvent.Properties[0].Value).Name
            InterfaceIndex  = $thisEvent.Properties[0].Value

            Destination     = $Destination # Mandatory
            sourceMac       = $sourceMac   # Mandatory
            EtherType       = $EtherType   # Mandatory
            ChassisID       = $ChassisID   # Mandatory

            PortDescription = $PortDescription # Optional
            SystemName      = $SystemName      # Optional

            NativeVLAN = $NativeVLAN        # IEEE 802.1 TLV:127 Subtype:1
            VLANID     = $VLANID            # IEEE 802.1 TLV:127 Subtype:3
            FrameSize  = $FrameSize         # IEEE 802.3 TLV:127 Subtype:4
            PFC        = $PFC | Sort-Object # IEEE 802.1 TLV:127 Subtype:11

            Bytes = $bytes # Raw Data from Packet
        }
    }

    Return $Table
}
#endregion LLDP

#region HostMap
Function Convert-CIDRToMask {
    param (
        [Parameter(Mandatory = $true)]
        [int] $PrefixLength
    )

    $bitString = ('1' * $prefixLength).PadRight(32, '0')

    [String] $MaskString = @()

    for($i = 0; $i -lt 32; $i += 8){
        $byteString = $bitString.Substring($i,8)
        $MaskString += "$([Convert]::ToInt32($byteString, 2))."
    }

    Return $MaskString.TrimEnd('.')
}

Function Convert-MaskToCIDR {
    param (
        [Parameter(Mandatory = $true)]
        [IPAddress] $SubnetMask
    )

    [String] $binaryString = @()
    $SubnetMask.GetAddressBytes() | ForEach-Object { $binaryString += [Convert]::ToString($_, 2) }

    Return $binaryString.TrimEnd('0').Length
}

Function Convert-IPv4ToInt {
    Param (
        [Parameter(Mandatory = $true)]
        [IPAddress] $IPv4Address
    )

    $bytes = $IPv4Address.GetAddressBytes()

    Return [System.BitConverter]::ToUInt32($bytes,0)
}

Function Convert-IntToIPv4 {
    Param (
        [Parameter(Mandatory = $true)]
        [uint32]$Integer
    )

    $bytes = [System.BitConverter]::GetBytes($Integer)

    Return ([IPAddress]($bytes)).ToString()
}

Class InterfaceDetails {
    [String] $IPAddress
    [String] $SubnetMask
    [String] $PrefixLength

    [String] $Network
    [String] $Subnet
    [String] $VLAN

    [string] $NetAdapterHostVNICName
    [string] $VMNetworkAdapterName
}
#endregion Host Map

#endregion Helper Functions

#region Exportable
function Test-FabricInfo {
    <#
    .SYNOPSIS
        Verifies prerequisites to running the other cmdlets in this module

    .EXAMPLE
        Test-FabricInfo

    .NOTES
        Author: Windows Core Networking team @ Microsoft

        Please file issues on GitHub @ GitHub.com/Microsoft/DataCenterBridging

    .LINK
        Windows Networking Blog     : https://aka.ms/MSFTNetworkBlog
    #>

    [CmdletBinding(DefaultParameterSetName = 'InterfaceNames')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName = 'InterfaceNames', Position=0)]
        [String[]] $InterfaceNames,

        [Parameter(Mandatory=$true, ParameterSetName = 'SwitchName')]
        [String] $SwitchName
    )

    $pass = '+'
    $fail = '-'
    $testsFailed = 0

    #region InterfaceNames
    If ($PSBoundParameters.ContainsKey('SwitchName')) {
        $VMSwitchTeam = Get-VMSwitchTeam -Name $SwitchName -ErrorAction SilentlyContinue

        if ($VMSwitchTeam) { $Interfaces = Get-Interfaces -SwitchName $SwitchName }
        Else { Write-Host "`'$SwitchName`' is not a Switch Embedded Team" -ForegroundColor Red ; break }
    }
    Elseif ($PSBoundParameters.ContainsKey('InterfaceNames')) {
        $NetAdapters = Get-NetAdapter -Name $InterfaceNames -ErrorAction SilentlyContinue
        # Not sure I understand this PowerShell funkyness but if I have only 1 adapter, the 'Count' Method is not available
        #     Therefore, we need to check if there's only 1 interface name and make sure there's an entry in NetAdapters
        #     Or check that there are more than 1 adapter

        if ($NetAdapters.Count) { $AdapterCount = $NetAdapters.Count }
        elseif ($NetAdapters) { $AdapterCount = 1 }
        else { $AdapterCount = 0 }

        If (-not($InterfaceNames.Count -eq $AdapterCount)) {
            if ($NetAdapters) {
                foreach ($Adapter in ($InterfaceNames -notmatch $NetAdapters.Name)) {
                    Write-Host "The interface `'$Adapter`' was not found" -ForegroundColor Red
                }
            }
            Else { Write-Host "No interfaces found with the specified names" -ForegroundColor Red }

            break
        }
        Else { $Interfaces = Get-Interfaces -InterfaceNames $InterfaceNames }
    }

    $remainingIndexes = $Interfaces.ifIndex

    foreach ($interface in $Interfaces) {
        if ($interface.Status -eq 'Up') { $PassFail = $pass }
        Else { $PassFail = $fail; $testsFailed ++ }

        if (-not($PassFail)) { throw "[$PassFail] Is Up: $($interface.Name)"}
        else { Write-Host "[$PassFail] Is Up: $($interface.Name)" }

        Remove-Variable PassFail -ErrorAction SilentlyContinue

        if ($Interface.MediaType -eq '802.3') { $PassFail = $pass }
        Else { $PassFail = $fail; $testsFailed ++ }

        if (-not($PassFail)) { throw "[$PassFail] Is MediaType 802.3: $($interface.Name)"}
        else { Write-Host "[$PassFail] Is MediaType 802.3: $($interface.Name)" }

        Remove-Variable PassFail -ErrorAction SilentlyContinue
    }
    #endregion InterfaceNames

    #region LLDP RSAT Tools Install
    $isLLDPInstalled = Get-WindowsFeature 'RSAT-DataCenterBridging-LLDP-Tools'

    if ($isLLDPInstalled.Installed) { $PassFail = $pass }
    Else { $PassFail = $fail; $testsFailed ++ }

    Write-Host "[$PassFail] Is Installed: RSAT-DataCenterBridging-LLDP-Tools"
    Remove-Variable PassFail, isLLDPInstalled -ErrorAction SilentlyContinue
    #endregion

    #region Event log exists and is enabled
    $isEvtLogEnabled = Get-WinEvent -ListLog 'Microsoft-Windows-LinkLayerDiscoveryProtocol/Diagnostic' -ErrorAction SilentlyContinue

    if ($isEvtLogEnabled) { $PassFail = $pass }
    Else { $PassFail = $fail; $testsFailed ++ }

    Write-Host "[$PassFail] Is Found: Event Log (Microsoft-Windows-LinkLayerDiscoveryProtocol/Diagnostic)"
    Remove-Variable PassFail -ErrorAction SilentlyContinue

    if ($isEvtLogEnabled.IsEnabled) { $PassFail = $pass }
    Else { $PassFail = $fail; $testsFailed ++ }

    Write-Host "[$PassFail] Is Enabled: Event Log (Microsoft-Windows-LinkLayerDiscoveryProtocol/Diagnostic)"
    Remove-Variable PassFail -ErrorAction SilentlyContinue

    if ($isEvtLogEnabled.FileSize -lt ($isEvtLogEnabled.MaximumSizeInBytes * .9)) { $PassFail = $pass }
    Else { $PassFail = $fail; $testsFailed ++ }

    Write-Host "[$PassFail] Is NOT Full: Microsoft-Windows-LinkLayerDiscoveryProtocol/Diagnostic"
    Remove-Variable PassFail -ErrorAction SilentlyContinue
    #endregion

    #region Get Fabric Info
    $global:IndexesMissingEvents = $Null
    $event = Get-LLDPEvents -RemainingIndexes $remainingIndexes

    $remainingIndexes | ForEach-Object {
        $thisRemainingIndex = $_

        if ($thisRemainingIndex -notin $global:IndexesMissingEvents) {
            $PassFail = $Pass

            Write-Host "[$PassFail] Is Found: LLDP Packet for index $thisRemainingIndex"
            Remove-Variable PassFail -ErrorAction SilentlyContinue
        }
        Else {
            $testsFailed ++
            $PassFail = $fail

            Write-Host "[$PassFail] Is Found: LLDP Packet for index $thisRemainingIndex"
            Remove-Variable PassFail -ErrorAction SilentlyContinue
        }
    }
    #endregion

    if ($testsFailed -eq 0) { Write-Host 'Successfully passed all tests' -ForegroundColor Green }
    else { Write-Host "Failed $testsFailed tests. Please review the output before continuing" -ForegroundColor Red }
}

function Enable-FabricInfo {
    param (
        [Parameter(Mandatory=$true, ParameterSetName = 'InterfaceNames', Position=0)]
        [String[]] $InterfaceNames,

        [Parameter(Mandatory=$true, ParameterSetName = 'SwitchName')]
        [String] $SwitchName
    )

    $LLDPFeature = Get-WindowsFeature -Name RSAT-DataCenterBridging-LLDP-Tools
    if ($LLDPFeature.InstallState -ne 'Installed') { Install-WindowsFeature -Name RSAT-DataCenterBridging-LLDP-Tools }

    # Enable NetLLDPAgent and get logs
    $LLDPLog = Get-WinEvent -ListLog Microsoft-Windows-LinkLayerDiscoveryProtocol/Diagnostic

    if ($LLDPLog.FileSize -gt ($LLDPLog.MaximumSizeInBytes * .9)) {
        $LLDPLog.IsEnabled = $false
        $LLDPLog.SaveChanges()
    }

    if ($LLDPLog.IsEnabled -eq $false) {
        $LLDPLog.IsEnabled = $true
        $LLDPLog.SaveChanges()
    }

    If ($PSBoundParameters.ContainsKey('SwitchName')) {
        $VMSwitch     = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
        $VMSwitchTeam = Get-VMSwitchTeam -Name $SwitchName -ErrorAction SilentlyContinue

        if ($VMSwitch -and $VMSwitchTeam) { $Interfaces = Get-Interfaces -SwitchName $SwitchName }
        Else { Write-Host "`'$SwitchName`' is not a Switch Embedded Team" -ForegroundColor Red ; break }
    }
    Elseif ($PSBoundParameters.ContainsKey('InterfaceNames')) {
        $NetAdapters = Get-NetAdapter -Name $InterfaceNames -ErrorAction SilentlyContinue
        # Not sure I understand this PowerShell funkyness but if I have only 1 adapter, the 'Count' Method is not available
        #     Therefore, we need to check if there's only 1 interface name and make sure there's an entry in NetAdapters
        #     Or check that there are more than 1 adapter

        if ($NetAdapters.Count) { $AdapterCount = $NetAdapters.Count }
        elseif ($NetAdapters) { $AdapterCount = 1 }
        else { $AdapterCount = 0 }

        If (-not($InterfaceNames.Count -eq $AdapterCount)) {
            if ($NetAdapters) {
                foreach ($Adapter in ($InterfaceNames -notmatch $NetAdapters.Name)) {
                    Write-Host "The interface `'$Adapter`' was not found" -ForegroundColor Red
                }
            }
            Else { Write-Host "No interfaces found with the specified names" -ForegroundColor Red }

            break
        }
        Else { $Interfaces = Get-Interfaces -InterfaceNames $InterfaceNames }
    }

    $remainingIndexes = $Interfaces.ifIndex

    Enable-NetLldpAgent -InterfaceIndex $remainingIndexes

    Write-Verbose 'LLDP has been enabled for the specified interfaces; LLDP packets are typically sent every 30 seconds'
    Write-Host    'Please run Test-FabricInfo to determine if all requirements have been met'
}

function Get-FabricInfo {
    param (
        [Parameter(Mandatory=$true, ParameterSetName = 'InterfaceNames', Position=0)]
        [String[]] $InterfaceNames,

        [Parameter(Mandatory=$true, ParameterSetName = 'SwitchName')]
        [String] $SwitchName
    )

    If ($PSBoundParameters.ContainsKey('SwitchName')) {
        $VMSwitch     = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
        $VMSwitchTeam = Get-VMSwitchTeam -Name $SwitchName -ErrorAction SilentlyContinue

        if ($VMSwitch -and $VMSwitchTeam) { $Interfaces = Get-Interfaces -SwitchName $SwitchName }
        Else { Write-Host "`'$SwitchName`' is not a Switch Embedded Team" -ForegroundColor Red ; break }
    }
    Elseif ($PSBoundParameters.ContainsKey('InterfaceNames')) {
        $NetAdapters = Get-NetAdapter -Name $InterfaceNames -ErrorAction SilentlyContinue
        # Not sure I understand this PowerShell funkyness but if I have only 1 adapter, the 'Count' Method is not available
        #     Therefore, we need to check if there's only 1 interface name and make sure there's an entry in NetAdapters
        #     Or check that there are more than 1 adapter

        if ($NetAdapters.Count) { $AdapterCount = $NetAdapters.Count }
        elseif ($NetAdapters) { $AdapterCount = 1 }
        else { $AdapterCount = 0 }

        If (-not($InterfaceNames.Count -eq $AdapterCount)) {
            if ($NetAdapters) {
                foreach ($Adapter in ($InterfaceNames -notmatch $NetAdapters.Name)) {
                    Write-Host "The interface `'$Adapter`' was not found" -ForegroundColor Red
                }
            }
            Else { Write-Host "No interfaces found with the specified names" -ForegroundColor Red }

            break
        }
        Else { $Interfaces = Get-Interfaces -InterfaceNames $InterfaceNames }
    }

    $remainingIndexes = $Interfaces.ifIndex

    $event = Get-LLDPEvents -RemainingIndexes $remainingIndexes

    if ($event.count -ne $remainingIndexes.Count) {
        Write-Host "Could not find an LLDP Packet one or more of the interfaces specified. Please run Test-FabricInfo." -ForegroundColor Red
    }
    Else { $InterfaceTable = Parse-LLDPPacket -Events $event }

    #Convert To/From JSON to make a simple object with property names
    $JsonTable = $InterfaceTable | ConvertTo-Json
    $InterfaceTable = $JsonTable | ConvertFrom-Json

    Remove-Variable jsonTable -ErrorAction SilentlyContinue

    $ChassisGroups = $InterfaceTable | Group-Object ChassisID
    #$portOrder = $ChassisGroups.Group | Sort sourceMac | Select InterfaceName, InterfaceIndex, ChassisID, SourceMac

    $InterfaceDetails = @()
    $HostNetAdapters = @()
    $interfaceMap = @()

    $HostVNICTeamMap = Get-VMNetworkAdapterTeamMapping -ManagementOS | Where-Object NetAdapterName -in $Interfaces.Name
    $Interfaces | ForEach-Object {
        $thisInterface = $_
        $InterfaceBinding = Get-NetAdapterBinding -Name $thisInterface.Name -ComponentID ms_tcpip, vms_pp

        if (($InterfaceBinding | Where-Object ComponentID -eq 'vms_pp').Enabled -eq $true ) {
            $thisHostVNICParentAdapter = ($HostVNICTeamMap | Where-Object NetAdapterName -eq $thisInterface.Name).ParentAdapter
            $HostNetAdapterWithIP = Get-NetAdapter -Name $thisHostVNICParentAdapter.Name
        }
        Else { $HostNetAdapterWithIP = $thisInterface }

        $HostNetAdapterWithIP | ForEach-Object {
            $thisHostNetAdapter = $_
            $thisIP = Get-NetIPAddress -InterfaceIndex $thisHostNetAdapter.ifIndex -AddressFamily IPv4

            if ($thisIP) {
                $thisHostNetAdapterInterfaceDetails = [InterfaceDetails]::new()

                $thisHostNetAdapterInterfaceDetails.IpAddress    = $thisIP.IPAddress
                $thisHostNetAdapterInterfaceDetails.PrefixLength = $thisIP.PrefixLength
                $thisHostNetAdapterInterfaceDetails.SubnetMask = Convert-CIDRToMask -PrefixLength $thisIP.PrefixLength

                $SubNetInInt = Convert-IPv4ToInt -IPv4Address $thisHostNetAdapterInterfaceDetails.SubnetMask
                $IPInInt     = Convert-IPv4ToInt -IPv4Address $thisHostNetAdapterInterfaceDetails.IPAddress
                $thisHostNetAdapterInterfaceDetails.Network = Convert-IntToIPv4 -Integer ($SubNetInInt -band $IPInInt)
                $thisHostNetAdapterInterfaceDetails.Subnet = "$($thisHostNetAdapterInterfaceDetails.Network)/$($thisHostNetAdapterInterfaceDetails.PrefixLength)"

                # Device is virtual
                if ($thisHostNetAdapter.ConnectorPresent -eq $false) {
                    if ($thisHostVNICParentAdapter.IsolationSetting.IsolationMode -eq 'VLAN') {
                        $thisHostNetAdapterInterfaceDetails.VLAN = $thisHostVNICParentAdapter.IsolationSetting.DefaultIsolationID
                    }

                    Switch ($thisHostVNICParentAdapter.VlanSetting.OperationMode) {
                        'Access' { $thisHostNetAdapterInterfaceDetails.VLAN = $thisHostVNICParentAdapter.VlanSetting.AccessVLANID }
                        'Trunk' { $thisHostNetAdapterInterfaceDetails.VLAN = $thisHostVNICParentAdapter.VlanSetting.NativeVlanId }
                    }

                    $thisHostNetAdapterInterfaceDetails.VMNetworkAdapterName = $thisHostVNICParentAdapter.Name
                    $thisHostNetAdapterInterfaceDetails.NetAdapterHostVNICName = $HostNetAdapterWithIP.Name
                }
                Else {
                    $thisHostNetAdapterInterfaceDetails.VLAN = (Get-NetAdapterAdvancedProperty -Name $thisHostNetAdapter.Name -RegistryKeyword VLANID -ErrorAction SilentlyContinue).RegistryValue
                }

                $interfaceDetails = [ordered] @{
                    IPAddress    = $thisHostNetAdapterInterfaceDetails.IPAddress
                    SubnetMask   = $thisHostNetAdapterInterfaceDetails.SubnetMask
                    PrefixLength = $thisHostNetAdapterInterfaceDetails.PrefixLength
                    Network      = $thisHostNetAdapterInterfaceDetails.Network

                    Subnet = $thisHostNetAdapterInterfaceDetails.Subnet
                    VLAN   = $thisHostNetAdapterInterfaceDetails.VLAN

                    InterfaceName  = $thisInterface.Name
                    InterfaceIndex = $thisInterface.IfIndex

                    NetAdapterHostVNICName = $thisHostNetAdapterInterfaceDetails.NetAdapterHostVNICName
                    VMNetworkAdapterName   = $thisHostNetAdapterInterfaceDetails.VMNetworkAdapterName
                }

                #Convert To/From JSON to make a simple object with property names
                $JsonTable = $interfaceDetails | ConvertTo-Json
                $interfaceDetails = $JsonTable | ConvertFrom-Json

                $interfaceMap += $interfaceDetails
            }
        }
    }

    $Mapping = @{}
    $interfaces | ForEach-Object {
        $thisInterfaceName = $_.Name
        $Mapping.$_ += @{
            Fabric = $InterfaceTable | Where-Object InterfaceName -eq $thisInterfaceName
            InterfaceDetails = $interfaceMap | Where-Object InterfaceName -eq $thisInterfaceName
        }
    }

    $Mapping += @{ ChassisGroups = $ChassisGroups }

    return $Mapping
}

function Start-FabricCapture {
    <#
    .SYNOPSIS
        Performs a packet capture of LLDP packets for the specified interfaces

    .EXAMPLE
        Start-FabricCapture

    .NOTES
        Author: Windows Core Networking team @ Microsoft

        Please file issues on GitHub @ GitHub.com/Microsoft/DataCenterBridging

    .LINK
        Windows Networking Blog     : https://aka.ms/MSFTNetworkBlog
    #>

    [CmdletBinding(DefaultParameterSetName = 'InterfaceNames')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName = 'InterfaceNames', Position=0)]
        [String[]] $InterfaceNames,

        [Parameter(Mandatory=$true, ParameterSetName = 'SwitchName')]
        [String] $SwitchName,

        #Typical LLDP interval is 30 seconds, so adding 1 to ensure we capture something
        [Parameter(Mandatory=$false)]
        [int] $CaptureTime = 31
    )

    #region InterfaceNames
    If ($PSBoundParameters.ContainsKey('SwitchName')) {
        $VMSwitchTeam = Get-VMSwitchTeam -Name $SwitchName -ErrorAction SilentlyContinue

        if ($VMSwitchTeam) { $Interfaces = Get-Interfaces -SwitchName $SwitchName }
        Else { Write-Host "`'$SwitchName`' is not a Switch Embedded Team" -ForegroundColor Red ; break }
    }
    Elseif ($PSBoundParameters.ContainsKey('InterfaceNames')) {
        $NetAdapters = Get-NetAdapter -Name $InterfaceNames -ErrorAction SilentlyContinue
        # Not sure I understand this PowerShell funkyness but if I have only 1 adapter, the 'Count' Method is not available
        #     Therefore, we need to check if there's only 1 interface name and make sure there's an entry in NetAdapters
        #     Or check that there are more than 1 adapter

        if ($NetAdapters.Count) { $AdapterCount = $NetAdapters.Count }
        elseif ($NetAdapters) { $AdapterCount = 1 }
        else { $AdapterCount = 0 }

        If (-not($InterfaceNames.Count -eq $AdapterCount)) {
            if ($NetAdapters) {
                foreach ($Adapter in ($InterfaceNames -notmatch $NetAdapters.Name)) {
                    Write-Host "The interface `'$Adapter`' was not found" -ForegroundColor Red
                }
            }
            Else { Write-Host "No interfaces found with the specified names" -ForegroundColor Red }

            break
        }
        Else { $Interfaces = Get-Interfaces -InterfaceNames $InterfaceNames }
    }
    #endregion InterfaceNames

    <# Won't use the powershell cmdlets because we want to capture from Interface pNIC01 only
     # LLDP uses multicast to send the port data and therefore src/dst address doesn't match to the pNIC#>

    # Ensuring no previous messes exist
    $interfaceNames | ForEach-Object {
        netsh.exe trace stop session=$_ | Out-Null
        Get-NetEventSession | Stop-NetEventSession -ErrorAction SilentlyContinue
        Get-NetEventSession | Remove-NetEventSession -ErrorAction SilentlyContinue
    }

    New-Item -Path "$PSScriptRoot\Capture" -ItemType Directory -Force | Out-Null
    Write-Host "Beginning capture..."

    $StartTime = Get-Date -format:'ddHHmmss'
    $interfaceNames | ForEach-Object {
        # netsh trace show CaptureFilterHelp has a ton of filter information
        netsh.exe trace start CaptureInterface=$_ Ethernet.Type=0x88cc capture=yes session=$_ correlation=disabled report=disabled PacketTruncateBytes=65000 tracefile="$PSScriptRoot\capture\$StartTime$_.etl" | Out-Null
    }

    Write-Host "Sleeping during capture for $CaptureTime seconds"
    Start-Sleep -Seconds $CaptureTime

    Write-Host 'Capture complete'
    Write-Host 'Converting capture to WireShark format'

    $interfaceNames | ForEach-Object {
        # netsh trace show CaptureFilterHelp has a ton of filter information
        netsh.exe trace stop session=$_ | Out-Null

        & "$PSScriptRoot\capture\etl2pcapng.exe" "$PSScriptRoot\capture\$StartTime$_.etl" "$PSScriptRoot\capture\$StartTime$_.pcapng" | Out-Null

        Write-Host "`rETL Capture is available at: $("$PSScriptRoot\capture\$StartTime$_.etl")"
        Write-Host "Wireshark Capture is available at: $("$PSScriptRoot\capture\$StartTime$_.pcapng")"
    }
}
#endregion Exportable
#endregion FabricInfo