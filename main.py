import queue
from threading import Thread
from sys import argv
from deffile import *
from datetime import datetime

q = queue.Queue()


#######################################################################################
# ------------------------------ main part -------------------------------------------#
#######################################################################################

argv_dict = get_argv(argv)
username, password = get_user_pw()
starttime = datetime.now()
devices = get_devinfo("devices.yaml")

total_devices = len(devices)

print("-------------------------------------------------------------------------------------------------------")
print("ip address       hostname                 comment               queue/thread info                      ")
print("---------------  -----------------------  --------------------  ---------------------------------------")


for i in range(argv_dict["maxth"]):

    th = Thread(target=mconnect, args=(q, username, password))
    th.setDaemon(True)
    th.start()


for device in devices:
    q.put(device)

q.join()

count_fconnect, count_commit_error, count_ping_ma_error = write_logs(devices)
endtime = datetime.now() - starttime


#######################################################################################
# ------------------------------ last part -------------------------------------------#
#######################################################################################


print("")
print("--------------------------------------------------------------")
print("connection failed: {} commit error: {} ping error: {}\ntotal device number: {}".format(count_fconnect,
                                                                                              count_commit_error,
                                                                                              count_ping_ma_error,
                                                                                              total_devices))
print("elapsed time: {}".format(endtime))
print("--------------------------------------------------------------\n")
