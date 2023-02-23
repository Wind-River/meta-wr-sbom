# Overview
The meta-wr-sbom OpenEmbedded/Yocto layer is used to generate Software Bill of Materials (SBOM) of [Software Package Data Exchange (SPDX)](https://spdx.org/tools) format for Yocto-based projects. The SBOM file created by the layer using SPDX v2.2 specification will include accurate identification of software components, explicit mapping of relationships between components, and the association of security and licensing information with each component.

----------------------------------------------------------------------------------------
# Supported Yocto Project Versions
- [Yocto Project 1.6 (Daisy)](https://lists.yoctoproject.org/pipermail/yocto-announce/2014-April/000045.html)  
- [Yocto Project 1.7 (Dizzy)](https://lists.yoctoproject.org/pipermail/yocto-announce/2014-October/000053.html)  
- [Yocto Project 1.8 (Fido)](https://lists.yoctoproject.org/pipermail/yocto-announce/2015-April/000062.html)  
- [Yocto Project 2.0 (Jethro)](https://lists.yoctoproject.org/pipermail/yocto-announce/2015-November/000076.html)  
- [Yocto Project 2.1 (Krogoth)](https://lists.yoctoproject.org/pipermail/yocto-announce/2016-May/000089.html)  
- [Yocto Project 2.2 (Morty)](https://www.yoctoproject.org/pipermail/yocto-announce/2016-November/000101.html)  
- [Yocto Project 2.3 (Pyro)](https://lists.yoctoproject.org/pipermail/yocto-announce/2017-May/000112.html)  
- [Yocto Project 2.4 (Rocko)](https://lists.yoctoproject.org/pipermail/yocto-announce/2017-October/000125.html)   
- [Yocto Project 2.5 (Sumo)](https://lists.yoctoproject.org/pipermail/yocto-announce/2018-May/000136.html)  
- [Yocto Project 2.6 (Thud)](https://lists.yoctoproject.org/pipermail/yocto-announce/2018-November/000147.html)  
- [Yocto Project 2.7 (Warrior)](https://lists.yoctoproject.org/pipermail/yocto/2019-May/045028.html)  
- [Yocto Project 3.0 (Zeus)](https://lists.yoctoproject.org/pipermail/yocto/2019-October/047111.html)
- [Yocto Project 3.1 (Dunfell)](https://lists.yoctoproject.org/g/yocto/message/49201)  
- [Yocto Project 3.2 (Gatesgarth)](https://lists.yoctoproject.org/g/yocto/message/51262)  
- [Yocto Project 3.3 (Hardknott)](https://lists.yoctoproject.org/g/yocto-announce/message/215)  
- [Yocto Project 3.4 (Honister)](https://lists.yoctoproject.org/g/yocto-announce/message/229)  
- [Yocto Project 4.0 (Kirkstone)](https://lists.yoctoproject.org/g/yocto/message/56902)	  
- [Wind River Linux 9](https://docs.windriver.com/category/os-wind_river_linux_9)
- [Wind River Linux LTS17](https://docs.windriver.com/category/os_linux_lts_17)
- [Wind River Linux LTS18](https://docs.windriver.com/category/os_linux_lts_18)
- [Wind River Linux LTS19](https://docs.windriver.com/category/os_linux_lts_19)
- [Wind River Linux LTS21](https://docs.windriver.com/category/os_linux_lts_21)
- [Wind River Linux LTS22](https://docs.windriver.com/category/os_linux_lts_22)


----------------------------------------------------------------------------------------
## Requirements
***Yocto Version >=1.6 & <=2.1:***   
Python 2 version >= 2.7 must be installed on build host machine.  
  
***Yocto Version >= 2.2:***  
***Wind River Linux Version >= WRL9:***  
Python 3 version >= 3.7 must be installed on build host machine.  


----------------------------------------------------------------------------------------
## Quick Start
### Getting meta-wr-sbom
Clone the meta-wr-sbom repository (or unpack an archive of it) into the top-level directory of your yocto build project:
```bash
git clone https://github.com/Wind-River/meta-wr-sbom
```

### Adding the meta-wr-sbom layer to Your Build
At the top-level directory of your yocto build workspace, you can add the meta-wr-sbom layer to the build system by performing the following command:
```bash
source ../meta-wr-sbom/init_create_sbom
```

### Generating SBOM File
```bash
bitbake ${image_name}
```

The SBOM file of your yocto project will be generated as  **tmp/deploy/images/${machine}/${image_name}.spdx.json**.   
***************************************************************************************

# Supported Legacy Wind River Linux Versions
- [Wind River Linux 6](https://docs.windriver.com/category/os-wind_river_linux_6)
- [Wind River Linux 7](https://docs.windriver.com/category/os-wind_river_linux_7)
- [Wind River Linux 8](https://docs.windriver.com/category/os-wind_river_linux_8)

----------------------------------------------------------------------------------------
## Requirements
Python 2.7 or later version is required to be installed on build host.

## Quick Start
### Getting meta-wr-sbom
Clone the meta-wr-sbom repository (or unpack an archive of it) into the top-level directory of your project:
```bash
git clone https://github.com/Wind-River/meta-wr-sbom
```

### Adding the meta-wr-sbom layer to Your Build
At the top-level directory of your Wind River project, you can add the meta-wr-sbom layer to the build system by performing the following command:
```bash
source ../meta-wr-sbom/init_create_sbom
```

### Generating SBOM File
```bash
make
```

The SBOM file of your project will be generated as  **bitbake_build/tmp/deploy/images/${machine}/${image_name}.spdx.json**.   
***************************************************************************************

# Supported EOL Wind River Linux versions
- Wind River Linux 3
- [Wind River Linux 4](https://docs.windriver.com/category/os-wind_river_linux_4)
- [Wind River Linux 5](https://docs.windriver.com/category/os-wind_river_linux_5)

## Requirements
Python 2.7 or later version is required to be installed on build host.

## Quick Start
Fully build your project.

### Getting meta-wr-sbom
Clone the meta-wr-sbom repository (or unpack an archive of it) into the top-level directory of your project:
```bash
git clone https://github.com/Wind-River/meta-wr-sbom
```

### Generating SBOM File
At the top-level directory of your project directory, perform the following command:
```bash
python meta-wr-sbom/tool/gen_eol_wrl_sbom.py .
```

The SBOM file of your project will be generated as  **meta-wr-sbom/tool/${image_name}.spdx.json**.   
***************************************************************************************

# Supported Binary-based Linux Distribution Versions
- Debian
- Ubuntu
- Fedora
- CentOS
- Red Hat
- openSUSE
- SUSE
- Alpine

## Requirements
Bash shell in Linux.

## Quick Start
Download the shell script to the target Linux host and run the script in the host.

### Getting shell script
Download the shell script to the home directory of current user on target Linux host
```bash
cd ~
wget https://raw.githubusercontent.com/Wind-River/meta-wr-sbom/main/tool/gen_os_pkgs_manifest.sh
```

### Generating manifest file
At the home directory, perform the following commands:
```bash
chmod u+rx gen_os_pkgs_manifest.sh
./gen_os_pkgs_manifest.sh
```
Or specify a root filesystem path:
```bash
./gen_os_pkgs_manifest.sh -r /path/to/rootfs
```
The manifest file will be generated as  **os_packages.manifest.txt** in the current directory.
If the file is already present, the generated filename will be changed to **os_packages.manifest.txt.xxxxxxxxxx.txt**

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


