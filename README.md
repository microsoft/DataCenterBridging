[![Build status](https://ci.appveyor.com/api/projects/status/ohvjnqqu2o9ccq60?svg=true)](https://ci.appveyor.com/project/MSFTCoreNet/datacenterbridging)
[![downloads](https://img.shields.io/powershellgallery/dt/datacenterbridging.svg?label=downloads)](https://www.powershellgallery.com/packages/datacenterbridging)

# Description

This module includes two primary capabilities:

- DSC PowerShell module intended to deploy Data Center Bridging settings using https://aka.ms/Validate-DCB
- Link Layer Discovery Protocol (LLDP) 802.1AB parser for Windows for the following organizationally specific subtypes

| Name           | Organization | Subtype      |
| :------------- | :----------: | -----------: |
|  Port VLAN (Native VLAN) | 802.1 | 1 |
| VLAN Name | 802.1 | 3 |
| Priority-based Flow Control Configuration (PFC) | 802.1 | B |
| Maximum Frame Size   | 802.3 | 4 |

## :star: More by the Microsoft Core Networking team

Find more from the Core Networking team using the [MSFTNet](https://github.com/topics/msftnet) topic

# Installation

This module is part of MSFT.Network.Tools which can be installed using this command:
```Install-Module MSFT.Network.Tools```

Or install this module individually using this command:
```Install-Module DataCenterBridging```

To see all modules from the Microsoft Core Networking team, please use:
```Find-Module -Tag MSFTNet```

# Usage

Please refer to the following blog for information on how to use the FabricInfo tools [Troubleshooting Switch Misconfiguration](https://techcommunity.microsoft.com/t5/networking-blog/troubleshooting-switch-misconfiguration/ba-p/2223614)

# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
