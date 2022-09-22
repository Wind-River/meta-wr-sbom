# Overview
The meta-wr-sbom OpenEmbedded/Yocto layer is used to generate Software Bill of Materials (SBOM) of [Software Package Data Exchange (SPDX)](https://spdx.org/tools) format for Yocto-based projects. The SBOM file created by the layer using SPDX v2.2 specification will include accurate identification of software components, explicit mapping of relationships between components, and the association of security and licensing information with each component.

----------------------------------------------------------------------------------------
# Supported Yocto Project Versions
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
- Yocto Project 4.0 (Kirkstone)	  
- [Wind River Linux 9](https://docs.windriver.com/category/os-wind_river_linux_9)
- [Wind River Linux LTS17](https://docs.windriver.com/category/os_linux_lts_17)
- [Wind River Linux LTS18](https://docs.windriver.com/category/os_linux_lts_18)
- [Wind River Linux LTS19](https://docs.windriver.com/category/os_linux_lts_19)
- [Wind River Linux LTS21](https://docs.windriver.com/category/os_linux_lts_21)


----------------------------------------------------------------------------------------
# Requirements
The package of Python 3 version >= 3.7 must be installed on build host.


----------------------------------------------------------------------------------------
# Quick Start
## Getting meta-wr-sbom
Clone the meta-wr-sbom repository (or unpack an archive of it) into the top-level directory of your yocto build project:
```bash
git clone https://github.com/Wind-River/meta-wr-sbom -b main
```

## Adding the meta-wr-sbom layer to Your Build
At the top-level directory of your yocto build workspace, you can add the meta-wr-sbom layer to the build system by performing the following command:
```bash
source ../meta-wr-sbom/init_create_sbom
```

## Generating SBOM File
```bash
bitbake ${image_name}
```

The SBOM file of your yocto project will be generated at  **tmp/deploy/images/${machine}/${image_name}.spdx.json**.   

