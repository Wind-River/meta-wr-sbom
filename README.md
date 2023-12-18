# Overview
The meta-wr-sbom OpenEmbedded/Yocto layer is used to generate Software Bill of Materials (SBOM) of [Software Package Data Exchange (SPDX)](https://spdx.org/tools) format for Yocto-based projects. The SBOM file created by the layer using SPDX v2.2 specification will include accurate identification of software components, explicit mapping of relationships between components, and the association of security and licensing information with each component.  
Besides, vulnerability detection can be tried using a scanner like [Wind River Scanning Tool](https://studio.windriver.com/scan).  
For commercial support options with meta-wr-sbom or Wind River Scanning Tool, please contact [Wind River](https://support2.windriver.com/).  

----------------------------------------------------------------------------------------
# Supported Yocto Project Versions
- [Yocto Project 4.3 (Nanbield)](https://lists.yoctoproject.org/g/yocto/message/61647)	  
- [Yocto Project 4.2 (Mickledore)](https://lists.yoctoproject.org/g/yocto/message/59892)	  
- [Yocto Project 4.1 (Langdale)](https://lists.yoctoproject.org/g/yocto/message/58398)	  
- [Yocto Project 4.0 (Kirkstone)](https://lists.yoctoproject.org/g/yocto/message/56902)	  
- [Yocto Project 3.4 (Honister)](https://lists.yoctoproject.org/g/yocto-announce/message/229)  
- [Yocto Project 3.3 (Hardknott)](https://lists.yoctoproject.org/g/yocto-announce/message/215)  
- [Yocto Project 3.2 (Gatesgarth)](https://lists.yoctoproject.org/g/yocto/message/51262)  
- [Yocto Project 3.1 (Dunfell)](https://lists.yoctoproject.org/g/yocto/message/49201)  
- [Yocto Project 3.0 (Zeus)](https://lists.yoctoproject.org/pipermail/yocto/2019-October/047111.html)
- [Yocto Project 2.7 (Warrior)](https://lists.yoctoproject.org/pipermail/yocto/2019-May/045028.html)  
- [Yocto Project 2.6 (Thud)](https://lists.yoctoproject.org/pipermail/yocto-announce/2018-November/000147.html)  
- [Yocto Project 2.5 (Sumo)](https://lists.yoctoproject.org/pipermail/yocto-announce/2018-May/000136.html)  
- [Yocto Project 2.4 (Rocko)](https://lists.yoctoproject.org/pipermail/yocto-announce/2017-October/000125.html)   
- [Yocto Project 2.3 (Pyro)](https://lists.yoctoproject.org/pipermail/yocto-announce/2017-May/000112.html)  
- [Yocto Project 2.2 (Morty)](https://www.yoctoproject.org/pipermail/yocto-announce/2016-November/000101.html)  
- [Wind River Linux LTS23](https://docs.windriver.com/category/os_linux_lts_23)
- [Wind River Linux LTS22](https://docs.windriver.com/category/os_linux_lts_22)
- [Wind River Linux LTS21](https://docs.windriver.com/category/os_linux_lts_21)
- [Wind River Linux LTS19](https://docs.windriver.com/category/os_linux_lts_19)
- [Wind River Linux LTS18](https://docs.windriver.com/category/os_linux_lts_18)
- [Wind River Linux LTS17](https://docs.windriver.com/category/os_linux_lts_17)
- [Wind River Linux 9](https://docs.windriver.com/category/os-wind_river_linux_9)



----------------------------------------------------------------------------------------
## Quick Start

### Requirement
Please create a new project to apply this tool to generate SBOM.

### Getting meta-wr-sbom
Clone the meta-wr-sbom repository (or unpack an archive of it) into the top-level directory of your yocto build project:
```bash
git clone https://github.com/Wind-River/meta-wr-sbom
```

If the Yocto version is lower than 4.2, or the Wind River Linux version is lower than LTS23, please **SKIP** this step. Otherwise, perform below checkout command:
```bash
cd meta-wr-sbom
git checkout 4.2_or_higher
```


### Adding the meta-wr-sbom layer to Your Build
Add the layer path into conf/bblayers.conf file:
```bash
BBLAYERS += "/xxx/.../meta-wr-sbom"
```

### Generating SBOM File
```bash
bitbake ${image_name}
```

The SBOM file of your yocto project will be generated as  **tmp/deploy/images/${machine}/${image_name}.spdx.json**.   
***************************************************************************************

## Generate Wind River Linux SBOM with earlier versions

The gen_spdx.py script is used for generating SBOM for WRLinux 5 - 8.

### Supported Wind River Linux versions

- [Wind River Linux 5](https://docs.windriver.com/category/os-wind_river_linux_5)
- [Wind River Linux 6](https://docs.windriver.com/category/os-wind_river_linux_6)
- [Wind River Linux 7](https://docs.windriver.com/category/os-wind_river_linux_7)
- [Wind River Linux 8](https://docs.windriver.com/category/os-wind_river_linux_8)

### Generating SBOM File
[Generate the old versions WRLinux SBOM](tools/USE_GEN_MANIFEST_PY.md) 

***************************************************************************************

## Generate Petalinux SBOM

### Supported Petalinux Versions
 
- [Petalinux v2019.2](https://support.xilinx.com/s/article/72950?language=en_US)
- [Petalinux v2022.1](https://support.xilinx.com/s/article/000033799?language=en_US)
- [Petalinux v2022.2](https://support.xilinx.com/s/article/000034483?language=en_US)
- [Petalinux v2023.1](https://support.xilinx.com/s/article/000035006?language=en_US)

### Generating SBOM File
[Generate Petalinux SBOM](petalinux-sbom.md) 


***************************************************************************************

# Legal Notices

All product names, logos, and brands are property of their respective owners. All company, 
product and service names used in this software are for identification purposes only. 
Wind River is a trademark of Wind River Systems, Inc.

Disclaimer of Warranty / No Support: Wind River does not provide support 
and maintenance services for this software, under Wind River’s standard 
Software Support and Maintenance Agreement or otherwise. Unless required 
by applicable law, Wind River provides the software (and each contributor 
provides its contribution) on an “AS IS” BASIS, WITHOUT WARRANTIES OF ANY 
KIND, either express or implied, including, without limitation, any warranties 
of TITLE, NONINFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A PARTICULAR 
PURPOSE. You are solely responsible for determining the appropriateness of 
using or redistributing the software and assume any risks associated with 
your exercise of permissions under the license.


