kill -9 `ps -ef | grep bin | grep -v grep | awk '{print $2}'`