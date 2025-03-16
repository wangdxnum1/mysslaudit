#!/bin/bash

# 查找所有 ./mysslaudit 进程的 PID
PIDS=$(ps aux | grep '[.]/mysslaudit' | awk '{print $2}')

# 如果没有找到进程则退出
if [ -z "$PIDS" ]; then
    echo "No running mysslaudit processes found."
    exit 0
fi

# 终止所有找到的 PID
echo "Terminating mysslaudit processes (PIDs): $PIDS"
sudo kill -9 $PIDS

# 检查是否成功
if [ $? -eq 0 ]; then
    echo "Successfully terminated all mysslaudit processes."
else
    echo "Failed to terminate some processes. Check permissions."
fi
