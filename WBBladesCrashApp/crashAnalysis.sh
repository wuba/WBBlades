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
   # echo 拼接前===$lineRes
   # 如果是C函数或者没有解析出.m所在行数，则直接输出
   if [[ $lineRes == *'['* && $lineRes == *']'* && $lineRes == *'.m'* ]]; then
     # echo "是OC方法"
     # 获取调用方式名
     method=${lineRes%% (in $appName) (*}
     # echo 方法名===$method
     # 获取文件名，并去除)
     filename=${lineRes#* (in $appName) (}
     filename=${filename/)/}
     # echo 文件名===$filename
     # 和原信息拼接起来
     echo "${tab_list[0]} ${tab_list[1]} $method $filename"
     # echo 拼接后==="${tab_list[0]} ${tab_list[1]} $method $filename"
   else
     # echo "是C函数"
     echo "${tab_list[0]} ${tab_list[1]} $lineRes"
     # echo 拼接后==="${tab_list[0]} ${tab_list[1]} $lineRes"
   fi
 else
   # 原样输出
   echo $aline
 fi
done
