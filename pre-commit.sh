#!/bin/bash

tester check --staged_files_only --docstring
rc=$?
if [[ $rc != 0 ]]; then
    exit $rc
fi

tester unit 
rc=$?
if [[ $rc != 0 ]]; then
    exit $rc
fi

printf "\nAll checks passed. To push to code review, please run: \033[95mgit push origin HEAD:refs/for/master\033[0m\n"
