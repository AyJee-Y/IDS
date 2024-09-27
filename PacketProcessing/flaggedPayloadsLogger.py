from threading import Lock
import pandas as pd
import os

log = ''
logLock = Lock()

def initializeLog(logLocation):
    global log
    if (os.path.isfile(logLocation)):
        log = pd.read_csv(logLocation)
    else:
        columns = ["TIME", "SRC_IP", "SRC_PORT", "DST_IP", "DST_PORT", "PROTOCOL", "SUSPICION", "DATA"]
        log = pd.DataFrame(columns=columns)

def addLogData(time, src_ip, src_port, dst_ip, dst_port, protocol, suspicion, data):
    global log
    global logLock

    packet_data = {
        "TIME":time, 
        "SRC_IP":src_ip,
        "SRC_PORT":src_port, 
        "DST_IP":dst_ip, 
        "DST_PORT":dst_port, 
        "PROTOCOL":protocol, 
        "SUSPICION":suspicion, 
        "DATA":data
    }

    logLock.acquire()
    log = pd.concat([log, pd.DataFrame([packet_data])], ignore_index=True)
    logLock.release()

def saveData(logLocation):
    global log
    global logLock

    logLock.acquire()
    log.to_csv(logLocation, index=False)
    logLock.release()