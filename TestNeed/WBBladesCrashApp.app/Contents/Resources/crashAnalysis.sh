#!/bin/sh

# 用法如：
# ./crashAnalysis.sh 58tongcheng ~/Downloads/dsym/crash.log ~/Downloads/dsym/58tongcheng.app.dSYM

# APP进程名
appName=$1
# 崩溃日志路径
logFilePath=$2
# dsym文件路径
dsymDir=$3

cat $logFilePath | while read aline
do
 # 设置IFS为分隔符，这里是空格
 IFS=' '
 # 使用read命令和-a选项将文本分割到数组中
 read -ra tab_list <<< "$aline"
 # 判断进程名是否为
 if [[ "${tab_list[1]}" == "$appName" ]]; then
   lineRes=`atos -arch arm64 -o $dsymDir -l ${tab_list[3]} ${tab_list[2]}`
   # echo $lineRes
   # 获取调用方式名
   method=${lineRes%% (in $appName) (*}
   # 获取文件名，并去除)
   filename=${lineRes#* (in $appName) (}
   filename=${filename/)/}
   # 和原信息拼接起来
   echo "${tab_list[0]} ${tab_list[1]} $method $filename"
 else
   # 原样输出
   echo $aline
 fi
done
