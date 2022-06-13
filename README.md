# wr-sbom
wr-sbom is use for generate Software Bill of Materials(SBOM) of a project.

----------------------------------------------------------------------------------------
# Support DISTRO versions
Yocto 2.2 - 4.0   
Wind River Linux 9, LTS17 - LTS21  


----------------------------------------------------------------------------------------
# Depends
The build environment needs to install python3 that the version no older than 3.7.


----------------------------------------------------------------------------------------
# To use
1. Download yocto or setup wrlinux;  

2. Download wr-sbom layer and switch to 'work' branch:  
	git clone ssh://git@bitbucket.wrs.com:7999/ccm-ps/wr-sbom.git -b work  

3. Create project work dir:  
	. oe-init-build-env ${workdir}  

4. Add the 'wr-sbom' layer:  
	bitbake-layers add-layer ../wr-sbom  

5. Enable the 'ccm-create-spdx' bbclass:  
	echo "INHERIT += 'ccm-create-spdx'" >> conf/local.conf  

6. Build the project:  
	bitbake ${image_name}  


The sbom is created under the image directory, and named as image name with postfix '.spdx.json';  
If enabled 'SPDX_INCLUDE_SOURCES', the patched source code tar files are placed under '${DEPLOY_DIR}/spdx/${MACHINE}/recipes/'.

