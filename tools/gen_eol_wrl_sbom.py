#
# Copyright (C) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: GPL-2.0-only
#

import os
import sys
import spdx
import datetime
import json

if len(sys.argv) < 2 or os.path.exists(sys.argv[1]) == False:
    print("Please specify a project directory to run the gen_eol_wrl_sbom script against.")
    #print("Project directory means the folder where [config.log] and [Makefile] file located.")
    sys.exit(1)

project_dir = sys.argv[1]

def gen_SPDXPattern():
    doc = spdx.SPDXDocument()
    doc.creationInfo.created = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    doc.creationInfo.creators.append("Tool: meta-wr-sbom gen_eol_wrl_sbom.py")
    doc.creationInfo.creators.append("Organization: WindRiver")
    doc.creationInfo.creators.append("Person: N/A")
    return doc
    
def wrl9andlater():
    doc = gen_SPDXPattern()
    wrl_version=""
    console_log_file_path = ""

    for root, dirs, files in os.walk(sys.argv[1]):
        if "console-latest.log" in files:
            console_log_file_path = os.path.join(root, "console-latest.log")
            break

    if len(console_log_file_path) > 0:
        console_log_file = open(console_log_file_path, 'r')
        console_log_file_lines = console_log_file.read().splitlines()
        console_log_file.close()

        for line in console_log_file_lines:
            
            if line.find("DISTRO_VERSION") == 0:
                
                wrl_version = line.replace("DISTRO_VERSION","")
                wrl_version = wrl_version.replace('"','')
                wrl_version = wrl_version.replace('=','')
                wrl_version = wrl_version.replace(' ','')
                #print("version:" +version)
            
            if line.find("DEFAULTTUNE") == 0:
                
                DEFAULTTUNE = line.replace("DEFAULTTUNE","")
                DEFAULTTUNE = DEFAULTTUNE.replace('"','')
                DEFAULTTUNE = DEFAULTTUNE.replace('=','')
                DEFAULTTUNE = DEFAULTTUNE.replace(' ','')
                #print("DEFAULTTUNE:" +DEFAULTTUNE)

    p1 = os.path.abspath(os.path.join(console_log_file_path, os.pardir))
    p2 = os.path.abspath(os.path.join(p1, os.pardir))
    p3 = os.path.abspath(os.path.join(p2, os.pardir))
    p4 = os.path.abspath(os.path.join(p3, os.pardir))
    
    work_dir = os.path.join(p4,"work")
    pkgs_dir = os.path.join(work_dir,DEFAULTTUNE+"-wrs-linux")

    if os.path.exists(pkgs_dir) == False:
        print("Can not found pkgs_dir!")
        sys.exit(1) 

    output_file_nm = "WRLinux"+wrl_version+".spdx.json"
    txt_file = open(os.path.join(os.path.dirname(__file__),output_file_nm), 'w')
    doc.name = DEFAULTTUNE+"-wrs-linux"
    doc.comment = "DISTRO: " + "WRLinux-" + wrl_version + "  ARCH: " + DEFAULTTUNE

    pkg_version = ""
    for pkg_name in os.listdir(pkgs_dir):
        for ver in os.listdir(os.path.join(pkgs_dir, pkg_name)):
            pos = ver.find("-")
            pkg_version = ver[:pos]
            #print(version)
        package = spdx.SPDXPackage()
        package.name = pkg_name
        package.SPDXID = "SPDXRef-%s-%s" % ("Recipe", pkg_name)
        package.versionInfo = pkg_version
        doc.packages.append(package)
    
    doc.to_json(txt_file, sort_keys=True)
    txt_file.close()
    print("SBOM file is generated as " + os.path.join(os.path.dirname(__file__),output_file_nm))
    print("Please share the SBOM file with Wind River.")

def wrl345678():

    doc = gen_SPDXPattern()
    # project dir contains bitbake folder will be treated as yocto based prj
    is_yocto_based_prj = os.path.exists(os.path.join(project_dir,"bitbake"))
    #print("is yocto prj: " + str(is_yocto_based_prj))

    DISTRO_NAME="WRLinux"
    DISTRO_VERSION=""

    WRL_MAJOR_VERSION=""
    WRL_RCPL_VERSION=""

    # get MAJOR_VERSION and RCPL_VERSION from Makefile first.
    makefile_file = open(makefile_path, 'r')
    makefile_lines = makefile_file.read().splitlines()
    makefile_file.close()

    major_version_token = "PACKAGE_VERSION = "
    rcpl_version_token = "RCPL_VERSION = "

    for line in makefile_lines:
        if line.find(major_version_token) > -1:
            WRL_MAJOR_VERSION = line.replace(major_version_token,"")
            # eg. WRL 4.3 => 4.3.0
            if WRL_MAJOR_VERSION.count('.')==1:
                WRL_MAJOR_VERSION = WRL_MAJOR_VERSION + ".0"
        
        if line.find(rcpl_version_token) > -1:
            WRL_RCPL_VERSION = line.replace(rcpl_version_token,"")

    # double check DISTRO_NAME and RCPL_VERSION from config.log
    config_file = open(config_log_file_path, 'r')
    config_log_lines = config_file.read().splitlines()
    config_file.close()

    for line in config_log_lines:
        if line.find("/configure") > -1:# find configure command line
            configure_items = line.split()
            #print(configure_items)
            for item in configure_items:
                
                # double check rcpl
                rcpl_start_token="--with-rcpl-version"
                if item.find(rcpl_start_token) > -1:
                    if WRL_RCPL_VERSION == "":
                        WRL_RCPL_VERSION = item.replace("--with-rcpl-version","")
                        WRL_RCPL_VERSION = WRL_RCPL_VERSION.replace("=","")
                        WRL_RCPL_VERSION = WRL_RCPL_VERSION.replace(" ","")

                #double check wrlinux major version
                wrlinux_start_token = "/wrlinux-"
                wrlinux_pos = item.find(wrlinux_start_token)
                if wrlinux_pos > -1:
                    if WRL_MAJOR_VERSION == "":
                        WRL_MAJOR_VERSION=item[wrlinux_pos+len(wrlinux_start_token)]
            break

    # get packages name from file [pkglist] to list
    pkglist_file = open(pkglist_file_path, 'r')
    pkglist = pkglist_file.read().splitlines()
    pkglist_file.close()

    # get all packages info from project build dir folders name
    build_folder_pkgs = []
    for item in os.listdir(build_folder_path):
        if os.path.isdir(os.path.join(build_folder_path, item)):
            if is_yocto_based_prj == False:
                build_folder_pkgs.append(item)
            else:
                pkg_fullpath = os.path.realpath(os.path.join(build_folder_path, item))
                build_folder_pkgs.append(pkg_fullpath)

    if WRL_RCPL_VERSION =="": # no rcpl info exist in config.log and makefile
            WRL_RCPL_VERSION = "0" 
    output_file_nm = DISTRO_NAME+WRL_MAJOR_VERSION+"."+WRL_RCPL_VERSION+".spdx.json"
    txt_file = open(os.path.join(os.path.dirname(__file__),output_file_nm), 'w')
    doc.name = DISTRO_NAME
    doc.comment = "DISTRO: " + "WRLinux-" + WRL_MAJOR_VERSION+"."+WRL_RCPL_VERSION + "  ARCH: " + ""
    

    for pkg_name in pkglist:

        # clean package name line string starts from "-" or contains "#"
        if pkg_name[0] == "-":
            pkg_name = pkg_name[1:]
        if pkg_name.find("#") > -1:
            pkg_name=pkg_name[0:pkg_name.find("#")]
        pkg_name = pkg_name.replace(" ","")

        is_found = False
        for pkg_dir_name in build_folder_pkgs:
            if is_yocto_based_prj == False:
                version = pkg_dir_name.replace(pkg_name,"")
                if version != "":
                    separator_pos = version.find("-")
                    if separator_pos == 0:
                        version = version[1:]
                        package = spdx.SPDXPackage()
                        package.name = pkg_name
                        package.SPDXID = "SPDXRef-%s-%s" % ("Recipe", pkg_name)
                        package.versionInfo = version
                        doc.packages.append(package)
                        is_found = True
                        break
            else: # yocto based project - from WRL5.0
                pkg_name_start_pos = pkg_dir_name.find("/"+pkg_name)
                if pkg_name_start_pos > -1:
                    version = pkg_dir_name[pkg_name_start_pos+len(pkg_name)+2:]
                    if version != "":
                        separator_pos = version.find("-")
                        if separator_pos > 1:
                            version = version[:separator_pos]
                            package = spdx.SPDXPackage()
                            package.name = pkg_name
                            package.SPDXID = "SPDXRef-%s-%s" % ("Recipe", pkg_name)
                            package.versionInfo = version
                            doc.packages.append(package)
                            is_found = True
                            break
        if is_found == False:
            package = spdx.SPDXPackage()
            package.name = pkg_name
            package.SPDXID = "SPDXRef-%s-%s" % ("Recipe", pkg_name)
            package.versionInfo = ""
            doc.packages.append(package)
    doc.to_json(txt_file, sort_keys=True)
    txt_file.close()
    print("SBOM file is generated as " + os.path.join(os.path.dirname(__file__),output_file_nm))
    print("Please share the SBOM file with Wind River.")

is_build_dir_exist = False
is_configlog_exist = False
is_Makefile_exist = False
is_pkglist_exist = False

console_latest_log = "console-latest.log"

build_folder_path = os.path.join(project_dir,"build")
if os.path.exists(build_folder_path) == False:
    is_build_dir_exist = False
    #print("Can not find build folder in project directory.")
else:
    is_build_dir_exist = True
    #print("Fully build project fisrt before run the script.")
    #sys.exit(1)

config_log_file_path = os.path.join(project_dir,"config.log")
if os.path.exists(config_log_file_path) == False:
    is_configlog_exist = False
    #print("Can not find config.log in project directory.")
else:
    is_configlog_exist = True
    #print("Fully build project fisrt before run the script.")
    #sys.exit(1)

makefile_path = os.path.join(project_dir,"Makefile")
if os.path.exists(makefile_path) == False:
    is_Makefile_exist = False
    #print("Can not find Makefile in project directory.")
else:
    is_Makefile_exist = True
    #print("Fully build project fisrt before run the script.")
    #sys.exit(1)

pkglist_file_path = os.path.join(project_dir,"pkglist")
if os.path.exists(pkglist_file_path) == False:
    #print("Can not find pkglist in project directory.")
    is_pkglist_exist = False
else:
    is_pkglist_exist = True
    #print("Fully build project fisrt before run the script.")
    #sys.exit(1)

if is_pkglist_exist and is_build_dir_exist and is_Makefile_exist and is_configlog_exist:
    wrl345678()
else:
    wrl9andlater()
