#!/usr/bin/env python3

# Script to extract information from image manifests
#
# Copyright (C) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: GPL-2.0-only
#

import os
import re
import sys
import json
import argparse
import logging
import traceback
import time
import sqlite3
from sqlite3 import Error
import tempfile
from collections import OrderedDict
from datetime import datetime, timezone

scripts_path = os.path.dirname(__file__)
for path in list(filter(lambda p: "bitbake/lib" in p, os.environ["PYTHONPATH"].split(':'))):
    lib_path = f"{path}/../../scripts/lib"
    if os.path.isfile(f"{lib_path}/scriptutils.py"):
        sys.path = sys.path + [lib_path]
        break
    else:
        print("scriptutils.py is not found, please check for PYTHONPATH contains a path to bibake/lib")
        sys.exit(1)

import scriptutils
logger = scriptutils.logger_create(os.path.basename(__file__))

import argparse_oe
import scriptpath
bitbakepath = scriptpath.add_bitbake_lib_path()
if not bitbakepath:
    logger.error("Unable to find bitbake by searching parent directory of this script or PATH")
    sys.exit(1)
logger.debug('Using standard bitbake path %s' % bitbakepath)
scriptpath.add_oe_lib_path()

import bb.tinfoil
import bb.utils
import oe.utils
import oe.recipeutils


license_refs = []
default_db_file = f"{os.environ['BUILDDIR']}/cache/wr-sbom/Linux-21-LTS.sqlite3"

recipe_file_lookup = {}
source_file_lookup = {}

def logTimedEvent(task_name, start_time):
	if(args.time):
		logger.debug(f"Completed subtask {task_name} in {time.time()-start_time}s")
	else:
		logger.debug(f"Completed substask {task_name}")

def create_connection(db_file):
    """ create a database connection to the SQLite database
        specified by the db_file
    :param db_file: database file
    :return: Connection object or None
    """
    conn = None
    try:
        conn = sqlite3.connect(db_file, check_same_thread=False)
    except Error as e:
        logger.error(e)

    return conn

def create_annotation(ref, note):
    from datetime import datetime, timezone

    creation_time = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    annotation = "Annotator: Tool: lxsbomtool - 1.0\n"
    annotation = f"{annotation}AnnotationDate: {creation_time}\n"
    annotation = f"{annotation}AnnotationType: OTHER\n"
    annotation = f"{annotation}SPDXREF: {ref}\n"
    annotation = f"{annotation}AnnotationComment:<text>{note}</text>\n"
    return annotation

def write_license_copyright(sha, sbom_fp):
#CREATE TABLE File (FileChecksum TEXT PRIMARY KEY, FileType TEXT, LicenseConcluded TEXT NOT NULL, LicenseInfoInFile TEXT NOT NULL, FileCopyrightText TEXT);
    cur = db_conn.cursor()
    cur.execute(f"SELECT * FROM File WHERE FileChecksum='{sha}'")
    rows = cur.fetchall()

    for row in rows:
        sbom_fp.write(f"FileType: {row[1]}\n")
        for lic in row[2].split(';'):
            sbom_fp.write(f"LicenseConcluded: {lic.lstrip().strip()}\n")
            for r in re.split(r"\sAND\s|\sOR\s|\sWITH\s", lic):
                license = r.lstrip().strip()
                if "LicenseRef" in license and not license in license_refs:
                    license_refs.append(license)

        for lic in row[3].split(';'):
            sbom_fp.write(f"LicenseInfoInFile: {lic.lstrip().strip()}\n")
            for r in re.split(r"\sAND\s|\sOR\s|\sWITH\s", lic):
                license = r.lstrip().strip()
                if "LicenseRef" in license and not license in license_refs:
                    license_refs.append(license)

        copyright = row[4].rstrip('\r\n')
        sbom_fp.write(f"FileCopyrightText: <text> {copyright} </text>\n")
        return True
    return False

def write_licenserefs(sbom_fp):
    tRef = time.time()
#CREATE TABLE LicenseReference (LicenseID TEXT NOT NULL PRIMARY KEY, ExtractedText TEXT NOT NULL, LicenseName TEXT NOT NULL DEFAULT 'NOASSERTION', LicenseCrossReference TEXT, LicenseComment TEXT);
    sbom_fp.write("\n\n##-----------------------------\n## Other License Information\n##-----------------------------\n")
    cur = db_conn.cursor()
    for licid in license_refs:
        cur.execute(f"SELECT * FROM LicenseReference WHERE LicenseID='{licid}'")
        rows = cur.fetchall()
        for row in rows:
            sbom_fp.write("\n\n## -------------------- License Information --------------------##\n")
            sbom_fp.write(f"LicenseID: {row[0]}\n")
            sbom_fp.write(f"ExtractedText: <text> {row[1]} </text>\n")
            sbom_fp.write(f"LicenseName: {row[2]}\n")
            sbom_fp.write(f"LicenseComment: <text> {row[4]} </text>\n")
            break
        else:
            sbom_fp.write("\n\n## -----------------Missing License Information ----------------##\n")
            sbom_fp.write(f"{create_annotation(licid, 'LicenseRef Data not available')}")

    license_refs.clear()
    logTimedEvent("write_licenserefs", tRef)

def map_json_from_document_ref(json, document_ref):
    doc_ref, spdx_ref = re.split('[:]', document_ref)
    for docs in json:
        if doc_ref == docs['externalDocumentId']:
            for index in index_json['documents']:
                if docs['spdxDocument'] == index['documentNamespace']:
                    return index['filename'], spdx_ref

def relationship_to_string(relationship):
    return f"{relationship['spdxElementId']} {relationship['relationshipType']} {relationship['relatedSpdxElement'].split(':')[-1]}"

def write_document_header(fp, name):
    fp.write("SPDXVersion: SPDX-2.2\n")
    fp.write("\n\n##------------------------------------------------------\n")
    fp.write("##                         SPDX 2.2 by Wind River\n")
    fp.write("##------------------------------------------------------\n")

    fp.write("\n\n##-------------------------\n")
    fp.write("## Document Information\n")
    fp.write("##-------------------------\n")
    fp.write("DataLicense: CC0-1.0\n")
    fp.write("SPDXID: SPDXRef-DOCUMENT\n")
    fp.write(f"DocumentName: {name}\n")
    fp.write("DocumentNamespace: http://spdx.windriver.com/Reports/2.2/<ID>\n")
    fp.write("DocumentComment: <text> This document is provided \"AS IS\" without any warranty, express or implied, including, but not limited to the Warranties of Merchantability, Fitness for a Particular Purpose, title and Non-Infringement. Wind River assumes no responsibility or liability for any errors or inaccuracies with respect to the information contained in it. Wind River may change the contents of this document at any time at its sole discretion, and Wind River shall have no liability whatsoever arising from recipient's use of this information. This file contains only computer generated SPDX data derived from computer automation.  Any legal obligations based on the content of this document should come from independent legal analysis and by reference to the notices and licenses contained within the open-source code itself. </text>\n")

def write_creation_info(fp, pkg_json):
    fp.write("\n\n##-------------------------\n")
    fp.write("## Creation Information\n")
    fp.write("##-------------------------\n")
    fp.write("Creator: Tool: lxsbomtool\n")
    fp.write(f"Created: {datetime.now().isoformat(timespec='seconds')}Z\n")
    fp.write(f"LicenseListVersion: {pkg_json['creationInfo']['licenseListVersion']}\n")

def write_pkg_spdx(pkg, relationship, sbom_fp):
    sbom_fp.write("\n\n##-------------------------\n")
    sbom_fp.write("## Package Information\n")
    sbom_fp.write("##-------------------------\n")
    sbom_fp.write(f"PackageName: {pkg['name']}-{pkg['versionInfo']}\n")
    sbom_fp.write(f"SPDXID: {pkg['SPDXID']}\n")
    sbom_fp.write("PackageDownloadLocation: NOASSERTION\n")

    # If a package does not have files, there is nothing to be Analyzed!
    if 'hasFiles' in pkg:
        sbom_fp.write(f"FilesAnalyzed: True\n")
        sbom_fp.write(f"PackageVerificationCode: {pkg['packageVerificationCode']['packageVerificationCodeValue']}\n")
    else:
        sbom_fp.write(f"FilesAnalyzed: False\n")
    #sbom_fp.write("PackageChecksum: NOASSERTION - need to add\n")

    sbom_fp.write(f"PackageLicenseConcluded: {pkg['licenseConcluded']}\n")
    sbom_fp.write(f"PackageLicenseDeclared: {pkg['licenseDeclared'].split(':')[-1]}\n")
    for file_license in pkg['licenseInfoFromFiles']:
        sbom_fp.write(f"PackageLicenseInfoFromFiles: {file_license}\n")
    sbom_fp.write("PackageCopyrightText: <text> NOASSERTION </text>\n")
    sbom_fp.write("PackageSummary: <text> Get from Recipe info </text>\n")
    sbom_fp.write(f"Relationship: SPDXRef-DOCUMENT {relationship['relationshipType']} {relationship['relatedSpdxElement'].split(':')[-1]}\n")
    sbom_fp.write("\n\n##-------------------------\n## File Information\n##-------------------------\n")

def write_file_spdx(file_data, sbom_fp):
    t = time.time()
    if "PackagedFile" in file_data['SPDXID']:
        sbom_fp.write("\n\n## ------------------- Packaged File ------------------\n##\n")
    else:
        sbom_fp.write("\n\n## -------------------- Source File -------------------\n##\n")

    sbom_fp.write(f"FileName: {file_data['fileName']}\n")
    sbom_fp.write(f"SPDXID: {file_data['SPDXID']}\n")
    sbom_fp.write(f"FileChecksum: {file_data['checksums'][0]['algorithm']}:{file_data['checksums'][0]['checksumValue']}\n")
    sbom_fp.write(f"FileChecksum: {file_data['checksums'][1]['algorithm']}:{file_data['checksums'][1]['checksumValue']}\n")
    if not write_license_copyright(f"SHA256:{file_data['checksums'][1]['checksumValue']}", sbom_fp) and not write_license_copyright(f"SHA1:{file_data['checksums'][0]['checksumValue']}", sbom_fp):
        for file_type in file_data['fileTypes']:
            sbom_fp.write(f"FileType: {file_type}\n")
        sbom_fp.write(f"LicenseConcluded: {file_data['licenseConcluded']}\n")
        for file_license in file_data['licenseInfoInFiles']:
            sbom_fp.write(f"LicenseInfoInFile: {file_license}\n")
        sbom_fp.write(f"FileCopyrightText: {file_data['copyrightText']}\n")
        # Add the annotation only for Source files since thats what's in the DB
        if not 'BINARY' in file_data['fileTypes']:
            comment = f"No IP Data for {file_data['fileName']} in {file_data['SPDXID']}"
            sbom_fp.write(f"{create_annotation(file_data['SPDXID'], comment)}")
    logTimedEvent("write_file_spdx" ,t)

def find_source_hash(json_stanza, relationship, pkg_name, sbom_fp):
    spdx_id = relationship['relatedSpdxElement']
    if "NOASSERTION" in spdx_id:
        return
    recipe_name, spdx_ref = map_json_from_document_ref(json_stanza['externalDocumentRefs'], spdx_id)
    if spdx_id.split(':')[1] in source_file_lookup:
        logger.debug("File already looked up, using cached data")
        write_file_spdx(source_file_lookup[spdx_id.split(":")[1]], sbom_fp)
        return

    ## Load recipe file, from file or lookup dictionary if possible
    recipe_json = {}
    if recipe_name in recipe_file_lookup:
        logger.debug('Recipe already looked up, using cached data')
        recipe_json = recipe_file_lookup[recipe_name]
    else:
        with open(f"{deploy_dir_spdx}/recipes/{recipe_name}") as fp:
            logger.debug(f"Recipe Name {recipe_name}")
            tRec = time.time()
            recipe_json = json.load(fp)
            recipe_file_lookup[recipe_name] = recipe_json
            logTimedEvent("load recipe JSON", tRec)

    ## Write source file entry from recipe
    for src_file in recipe_json['files']:
        if src_file['SPDXID'] == spdx_id.split(':')[1]:
            source_file_lookup[spdx_id.split(':')[1]] = src_file
            write_file_spdx(src_file, sbom_fp)
            break

def write_package_relationships(relationships, sbom_fp):
    sbom_fp.write("\n\n##-------------------------\n")
    sbom_fp.write("## Relationships\n")
    sbom_fp.write("##-------------------------\n")
    for rel in relationships:
        sbom_fp.write(f"Relationship: {relationship_to_string(rel)}\n")

def parse_package(pkg_json, pkg, pkg_relationship, sbom_fp):
    total_parsed_rel_list = [] 
    for spdx_pkg in pkg_json['packages']:
        if pkg == spdx_pkg['SPDXID']:
            write_pkg_spdx(spdx_pkg, pkg_relationship, sbom_fp)
            if not 'hasFiles' in spdx_pkg:
                continue
            for pkged_file in spdx_pkg['hasFiles']:
                for pkg_file in pkg_json['files']:
                    if pkged_file == pkg_file['SPDXID']:
                        pkg_filename = pkg_file['fileName']
                        spdxElementId = pkg_file['SPDXID']
                        file_relationship = ""

                        ## Find relationship for this file where it is a "child"
                        for relationship in pkg_json['relationships']:
                            if spdxElementId in relationship['relatedSpdxElement']:
                                write_file_spdx(pkg_file, sbom_fp)
                                total_parsed_rel_list.append(relationship)
                                break

                        parsed_rel_list = [rel for rel in pkg_json['relationships'] if spdxElementId in rel['spdxElementId']]
                        total_parsed_rel_list += parsed_rel_list 
                        ## Find relationships for this file where it is a "parent"
                        for relationship in parsed_rel_list:
                            time_temp = time.time()
                            find_source_hash(pkg_json, relationship, spdx_pkg['name'], sbom_fp)
                            logTimedEvent("find_source_hash on " + relationship["relatedSpdxElement"], time_temp)
    write_package_relationships(total_parsed_rel_list, sbom_fp)

def parse_relationship(rel):
    global succeeded
    global failed

    ## Find filename to parse
    filename, spdx_ref = map_json_from_document_ref(image_json["externalDocumentRefs"], rel["relatedSpdxElement"])
    package_name = filename.split('.spdx.json')[0]

    if args.packages and (not package_name in args.packages):
        return

    # A bit of preprocessing, setup and logging before parsing
    parse_logs[package_name] = {}
    logger.info(f"Parsing {len(parse_logs.keys())} of {total} {package_name}...")
    start = time.time()

    ## Parse package and write spdx file
    try:
        with open(f"{sbom_dir}/{package_name}.spdx", "w") as sbom_fp:
            write_document_header(sbom_fp, args.image)
            with open(f"{deploy_dir_spdx}/packages/{filename}") as pkg_fp:
                pkg_json = json.load(pkg_fp)
                write_creation_info(sbom_fp, pkg_json)
                parse_package(pkg_json, pkg_json['packages'][0]['SPDXID'], rel, sbom_fp)
            write_licenserefs(sbom_fp)
            succeeded += 1
            parse_logs[package_name]["parse_status"] = "succeeded"
    except KeyboardInterrupt:
        logger.warn("Caught KeyboardInterrupt")
        return
    except Exception as e:
        logger.error(f"ERROR While parsing {package_name}")
        logger.error(f"Exception: {e}")
        failed += 1
        parse_logs[package_name]["parse_status"] = "failed"
        parse_logs[package_name]["traceback"] = traceback.format_exc()
    finally:
        parse_logs[package_name]["time_elapsed"] = time.time() - start

def main():
    from pathlib import Path

    global db_conn
    global index_json
    global image_json
    global deploy_dir_spdx
    global deploy_dir_image
    global sbom_dir

    global parse_logs
    global succeeded
    global failed
    global total
    global args

	## Set up argument parser
    parser = argparse_oe.ArgumentParser(description="WindRiver SBOM Generation Tool")
    parser.add_argument('-d', '--debug', help='Enable debug output', action='store_true')
    parser.add_argument('-q', '--quiet', help='Print only errors', action='store_true')
    parser.add_argument('-D', '--db_file', help="IP Matching Database", action='store', default=default_db_file)
    parser.add_argument('-i', '--image', help="Image name to create SBOM from", action='store', default='wrlinux-image-small')
    parser.add_argument('-l', '--limit', help="Limit # of packages parsed, default is all", type=int, action='store', default=0)
    parser.add_argument('-p', '--packages', help="Scan package not image, can be used multiple times", action='append', type=str)
    parser.add_argument('-o', '--output_dir', help="Alternate output directory for SBOM files", action='store')
    parser.add_argument('-t', '--time', help='Enable timing output', action='store_true')
    args = parser.parse_args()

	## Setup logger and set important variables
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug(f"Debug Enabled: {args.db_file}")
    elif args.quiet:
        logger.setLevel(logging.ERROR)

    with bb.tinfoil.Tinfoil() as tinfoil:
        tinfoil.logger.setLevel(logger.getEffectiveLevel())
        tinfoil.prepare()

        deploy_dir_image = tinfoil.config_data.getVar('DEPLOY_DIR_IMAGE')
        deploy_dir_spdx = tinfoil.config_data.getVar('DEPLOY_DIR_SPDX')
        machine_arch = tinfoil.config_data.getVar('MACHINE_ARCH').replace('_', '-')

    total_time = time.time()

    ## Load image spdx json and relationships list
    machinearch = machine_arch
    image_fp = open(f"{deploy_dir_image}/{args.image}-{machinearch}.spdx.json")
    image_json = json.load(image_fp)
    relationships_list = list(filter(lambda x: x["relationshipType"] == "CONTAINS", image_json["relationships"]))
    ## Load the index spdx json to translate externalRefs
    index_fp = open(f"{deploy_dir_image}/{args.image}-{machinearch}.spdx.index.json")
    index_json = json.load(index_fp)

    ## check for the db_file and split files, create sqlite3 file if needed
    if not os.path.exists(default_db_file):
        if not os.path.exists(os.path.dirname(default_db_file)):
            os.makedirs(os.path.dirname(default_db_file))
        os.system(f"xzcat {scripts_path}/../../wr-sbom-dl-3.3/Linux-21-LTS.sqlite3.xz > {default_db_file}")

    db_conn = create_connection(args.db_file)

    ## Set output directory (create output dir if necessary)
    if args.output_dir:
        sbom_dir = args.output_dir
    else:
        sbom_dir = f"{deploy_dir_spdx}/wr-sbom"
    Path(sbom_dir).mkdir(parents=True, exist_ok=True)

    ## Initialize progress tracking variables
    succeeded = 0
    failed = 0
    parse_logs = {}

    ## Find total number of packages to parse
    if args.packages:
        total = len(args.packages)
    else:
        total = len(relationships_list)

    ## Parse each package to a single *.spdx file (based on the image relationships)
    for rel in relationships_list:
       parse_relationship(rel)
       # Limit package parsing
       if(args.limit != 0 and len(parse_logs.keys()) >= args.limit):
               break
    ## Output file generation report
    logger.info("----------SPDX File Generation Complete----------")
    logger.info(f"{succeeded} packages parsed successfully")
    logger.info(f"{failed} packages failed to parse")
    logger.info(f"{time.time()-total_time}s taken")

	## Dump parse logs to a json file
    with open(f"{sbom_dir}/parse_logs.json", "w") as plg_fp:
        json.dump(parse_logs, plg_fp)



if __name__ == '__main__':
    main()
