#!/bin/bash

tester check --staged_files_only
rc=$?
if [[ $rc != 0 ]]; then
    exit $rc
fi

tester unit --nose_cover_packages=enmutils.lib --cover_min_percentage 64
rc=$?
if [[ $rc != 0 ]]; then
    exit $rc
fi

printf "\nAll checks passed. To push to code review, please run: \033[95mgit push origin HEAD:refs/for/master\033[0m\n"
