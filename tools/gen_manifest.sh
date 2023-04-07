#/bin/bash
#
# Copyright (C) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: GPL-2.0-only
#

#####################################################################################
# Before execute the script:
#   1. The current path is the project build directory;
#   2. The project image had full build completed;
#   3. The 'bitbake' command is ready;
# 
# Execute the script:
#   ${the_path}/gen_manifest.sh target_image_name;
#
# The target_image_name is the image target to generate manifest, such as 'wrlinux-image-small'.
#
# If the script execute success, the manifest will generate at current directory.
#####################################################################################

f_output=manifest.lst
f_log=manifest.log

target_name=$1
ROOTFS_DIR=`find tmp*/work/*/${target_name}/*/ -maxdepth 1 -type d -name rootfs`

all_packages=`find tmp*/work/*/*/*/packages-split -maxdepth 1 -type d | grep -v packages-split$`

[ -f ${f_output} ] && rm ${f_output}
bitbake ${target_name} -e | grep -e '^DISTRO_VERSION=' -e '^DISTRO_NAME=' > ${f_output}
echo >> ${f_output}

echo  >> ${f_log}
echo  >> ${f_log}
echo "-------------- Start scanning -----------------" >> ${f_log}
echo "Searching the installed packages ..."
for d in ${all_packages}
do
	unset cur_package vertmp
	echo $d | awk -F/ '{print "cur_package="$(NF-3) " vertmp="$(NF-2) " : " $NF}' >> ${f_log}
	eval $(echo $d | awk -F/ '{print "cur_package="$(NF-3) " vertmp="$(NF-2)}')
	grep -q "^${cur_package}" ${f_output}
	if [ $? -eq 0 ]
	then
		echo "skip duplicate" >> ${f_log}
		continue
	fi

        pushd $d > /dev/null
        file_in_split=`find */ -type f 2>/dev/null | head -n1`
	if [ -z ${file_in_split} ]
	then
		popd > /dev/null
		echo "skip empty package" >> ${f_log}
		continue
	fi

	popd > /dev/null

        pkg_file=${file_in_split}

        if [ -e ${ROOTFS_DIR}/${pkg_file} ]
        then
		PV=${vertmp%-*}
		echo ${cur_package} ${PV%+git*} >> ${f_output}
	else
		echo "not install" >> ${f_log}
        fi
done

echo
echo
echo "./${f_output} created!"

