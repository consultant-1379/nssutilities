#!/usr/bin/env python
import os
import glob
import shutil

import click


EXCLUDED_SCRIPTS = ['__init__', '__main__', 'daemon', 'tester']

OTHER_LOCATION_SCRIPTS = {
    'hot_deploy_dps_jpa_ear': '.deploy'
}


def get_entry_scripts(package):
    package_module_map = {
        'production': os.path.join('ERICnssutilities_CXP9035994', 'nssutils')
    }
    package_folder_mapping = {
        'production': 'bin',
    }
    scripts = []
    scripts_paths = glob.glob(os.path.join(package_module_map[package], 'bin', '*.py'))
    for script in scripts_paths:
        file_path, _ = os.path.splitext(script)
        module_name = file_path.split('/')[-1]
        if module_name not in EXCLUDED_SCRIPTS:
            if module_name in OTHER_LOCATION_SCRIPTS:
                location = OTHER_LOCATION_SCRIPTS[module_name]
            else:
                location = package_folder_mapping[package]
            scripts.append((module_name, location))
    return scripts


@click.command()
@click.option('--package', type=click.Choice(['production']),
              help='Type of package for which scripts are copied to jenkins workspace.')
@click.option('--script_dir', type=click.Path(), default='.env')
def copy_bin_files(package='', script_dir=''):
    for script, location in get_entry_scripts(package):
        if not os.path.exists(location):
            os.makedirs(location)
        shutil.copy2(os.path.join(script_dir, 'bin', script), location)


if __name__ == '__main__':
    copy_bin_files()
