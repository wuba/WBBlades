#!/usr/bin/env bash

## Usage: sh ./search_symbol.sh <target directory> <symbol name>

count=$# # param count

if [[ $count -lt 2 ]]; then
    echo "Please enter the directory and keywords you want to search.\n"
    exit
fi

workdir=$1 # the directory to search
keyword=$2 # the symbole name you want to search

if [[ -e $workdir ]] && [[ -d $workdir ]]; then
    echo "The current working directory is:: $workdir\n"
else
    echo "Invalid directory, please check your input parameters."
    exit
fi

echo "The keyword you entered is $keyword\n"

search_liba() {
    dir=$1
    for lib in $(find $dir -type f -name "*.a");
    do
        cnt=$(strings $lib | grep $keyword -wc)
        if [[ $cnt -gt 0 ]]; then
            echo "$lib -> $keyword($cnt)"
        fi
    done
}

search_framework() {
    dir=$1
    for lib in $(find $dir -type d -name "*.framework");
    do
        lib_name=${lib##*/}
        lib_name_without_ext=${lib_name%.framework}
        lib_full_name=$lib/$lib_name_without_ext
        if [[ -e "$lib_full_name" ]]; then
            cnt=$(strings $lib_full_name | grep $keyword -wc)
            if [[ $cnt -gt 0 ]]; then
                echo "$lib_full_name -> $keyword($cnt)"
            fi
        fi
    done
}

search_liba $workdir
search_framework $workdir