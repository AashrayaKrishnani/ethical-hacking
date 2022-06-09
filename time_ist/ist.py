#!/usr/bin/env python3
import subprocess

import ntplib
from time import ctime
import re


def get_raw_time():
    while True:
        # noinspection PyBroadException
        try:
            ntp_client = ntplib.NTPClient()

            try:
                response = ntp_client.request('pool.ntp.org')
            except KeyboardInterrupt:
                print("[-] Keyboard Interrupt detected... Exiting...\n")
                exit(0)

            if response:
                break
        except:
            pass

    return ctime(response.tx_time)


def set_date(date, month, year):
    subprocess.call("date +%Y%m%d -s \"" + str(year) + str(month) + str(date) +"\"", shell=True)


def set_time(time):
    subprocess.call(" date +%T -s \"" + str(time) + "\"", shell=True)


def check_root_or_not():

    try:
        output = subprocess.check_output(" date +%T -s \"00:00:00\"", shell=True, stderr=subprocess.STDOUT)
    except:
        print("\n[-] Kindly re-run with root privileges.\n")
        exit(0)
        

def extract_month(data):
    if "Jan" in data:
        month = "01"
    elif "Feb" in data:
        month = "02"
    elif "Mar" in data:
        month = "03"
    elif "Apr" in data:
        month = "04"
    elif "May" in data:
        month = "05"
    elif "Jun" in data:
        month = "06"
    elif "Jul" in data:
        month = "07"
    elif "Aug" in data:
        month = "08"
    elif "Sep" in data:
        month = "09"
    elif "Oct" in data:
        month = "10"
    elif "Nov" in data:
        month = "11"
    elif "Dec" in data:
        month = "12"
        
    return month


def extract_date(data):
    date = re.findall(r" \d{1,2} ", data)
    if date:
        date = date[0]
    else:
        print("[-] Error extracting date.")
        exit(0)

    date = str(date).strip()
    return str('%02d' % int(date))


def extract_year(data):
    year = re.findall(r"\d\d\d\d", data)
    if year:
        year = year[0]
    else:
        print("[-] Error extracting year.")
        exit(0)

    return year


def extract_time(data):
    time = re.findall(r"\d\d:\d\d:\d\d", data)
    if time:
        time = time[0]
    else:
        print("[-] Error extracting time.")
        exit(0)

    return time


check_root_or_not()

time_raw = str(get_raw_time())

time_month = extract_month(time_raw)
time_year = extract_year(time_raw)
time_date = extract_date(time_raw)
time_time = extract_time(time_raw)

set_date(year=time_year, month=time_month, date=time_date)
set_time(time=time_time)
