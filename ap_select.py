import subprocess
import threading
import time
import json
import os
from datetime import datetime 
import threading
import speedtest
import queue
import subprocess
import csv
import signal
import sys
import mysql.connector

def merge(arr, start, mid, end): 
    l_size = mid - start + 1
    r_size = end- mid 
    left = [0] * (l_size) 
    rt = [0] * (r_size)  
    for i in range(0 , l_size): 
        left[i] = arr[start + i] 
    for j in range(0 , r_size): 
        rt[j] = arr[mid + 1 + j] 
    (i, j, k) = (0, 0, start)     
    while i < l_size and j < r_size : 
        if left[i][1] > rt[j][1]: 
            arr[k] = left[i] 
            i += 1
        elif left[i][1] == rt[j][1]:
            if left[i][2] >= rt[j][2]:
                arr[k] = left[i]
                i += 1
            else:
                arr[k] = rt[j]
                j += 1
        else: 
            arr[k] = rt[j] 
            j += 1
        k += 1
    while i < l_size: 
        arr[k] = left[i] 
        i += 1
        k += 1
    while j < r_size: 
        arr[k] = rt[j] 
        j += 1
        k += 1

def msort(arr,start,end): 
    if start < end: 
        mid = (start+end)//2
        msort(arr, start, mid) 
        msort(arr, mid+1, end) 
        merge(arr, start, mid, end)


def qsort(l,start,end):
   if start < end:
       pivot = l[end][1]
       i = start - 1
       for j in range(start,end):
           if l[j][1] <= pivot:
               i += 1
               (l[i], l[j]) = (l[j], l[i])
       (l[i+1], l[end]) = (l[end], l[i+1])
       
       qsort(l,start,i)
       qsort(l,i+2,end)
    
def fetch_aps_data():
    
        shell_cmd = subprocess.Popen(["iwlist","scanning"],stdout=subprocess.PIPE)
        shell_op = shell_cmd.stdout.readlines()
        
        aps_data = {}
        ap_inf = {}
        ap_essid = ''
        
        for inf in shell_op:
            if 'Cell' in str(inf):
                ap_inf['SSID'] = str(inf[29:46].decode("utf-8"))
            elif 'ESSID' in str(inf):
                ap_essid = str(inf[27:-2].decode("utf-8"))
            elif 'Frequency' in str(inf):
                ap_inf['Frequency'] = str(inf[30:-1].decode("utf-8"))
            elif 'Bit Rates' in str(inf):
                ap_inf['Bit Rate'] = str(inf[30:-1].decode("utf-8"))
            elif 'Signal' in str(inf):
                ap_inf['Signal Level'] = (int(str(inf.decode("utf-8")).strip().split("=")[2].split("/")[0]))
                aps_data[ap_essid] = ap_inf.copy()
        return aps_data

def print_aps_data():
        
            sort_list = []
            ap_scan = fetch_aps_data()
            for inf in ap_scan:
                  sort_list.append([inf,ap_scan[inf]['Signal Level']])
            
            qsort(sort_list,0,len(sort_list)-1)
            for inf in reversed(sort_list):
                print(inf[0] + " " + ap_scan[inf[0]]['SSID'] + " " + ap_scan[inf[0]]['Frequency'] + " " + ap_scan[inf[0]]['Bit Rate'] + " " +str(ap_scan[inf[0]]['Signal Level']))
            

def json_dump(data):
    with open("fingerprints.json","w") as fw:
                json.dump(data,fw,indent=4)

def loc_rec():
        fingerprint = {}
        visit_threshold = 15     #prev 100
        data = {'avg_signal':0, 'responses':0}
        count = 1
        while count <= 10:
            ap_scan1 = fetch_aps_data()
            for inf in ap_scan1:
                if ap_scan1[inf]['SSID'] not in fingerprint:
                    data['avg_signal'] = ap_scan1[inf]['Signal Level']
                    data['responses'] = 1
                else:
                    data['avg_signal'] = (fingerprint[ap_scan1[inf]['SSID']]['avg_signal'] + ap_scan1[inf]['Signal Level'])/2
                    data['responses'] = fingerprint[ap_scan1[inf]['SSID']]['responses'] + 1
                fingerprint[ap_scan1[inf]['SSID']] = data.copy()   
            count += 1
            
        sorted_fingerprint = []
        #Fingerprints
        for fprint in fingerprint:
            sorted_fingerprint.append([fprint,fingerprint[fprint]['responses'],fingerprint[fprint]['avg_signal']])
        print(sorted_fingerprint)
        msort(sorted_fingerprint,0,len(sorted_fingerprint)-1)
        #candidate_fingerprints = {}
        if len(sorted_fingerprint) >= 4: 
            for inf in range(4):
                candidate_fingerprints[sorted_fingerprint[inf][0]] = fingerprint[sorted_fingerprint[inf][0]]
        else:
            for inf in range(len(sorted_fingerprint)):
                candidate_fingerprints[sorted_fingerprint[inf][0]] = fingerprint[sorted_fingerprint[inf][0]]
        #candidate fingerprints
        """print("Candidate fingerprints:")
        for inf in candidate_fingerprints:
            print(inf +" " + str(candidate_fingerprints[inf]['avg_signal']))"""
        
        if (not os.path.getsize("fingerprints.json")):
            data = {}
            data["fingerprints"] = candidate_fingerprints
            data["visit_count"] = 1
            
            with open("fingerprints.json","w") as fw:
                json.dump([data],fw,indent=4)
        else:
            data = []
            with open('fingerprints.json') as f:
                data = json.load(f)
                
            for inf in data:
                count = 0
                for fp in candidate_fingerprints:
                    if fp in inf['fingerprints']:
                        count += 1
                if count >= 3:
                    print("Location is peviously visited!!!")
                    if inf['visit_count'] < visit_threshold :
                        #not visited frequently
                        inf['visit_count'] += 1
                        json_dump(data)
                        return 1
                    else:
                        #visited frequently
                        json_dump(data)
                        return 0
            data.append({'fingerprints':candidate_fingerprints,'visit_count':1})
            with open("fingerprints.json","w") as fw:
                json.dump(data,fw,indent=4)
            return 1



def sig_str(ap_selected):
    shell_cmd = subprocess.Popen(["iwlist","scanning"],stdout=subprocess.PIPE)
    shell_op = shell_cmd.stdout.readlines()
        
    aps_data = {}
    ap_inf = {}
    ap_essid = ''
        
    for inf in shell_op:
        if 'Cell' in str(inf):
            ap_inf['SSID'] = str(inf[29:46].decode("utf-8"))
        elif 'ESSID' in str(inf):
            ap_essid = str(inf[27:-2].decode("utf-8"))
        elif 'Frequency' in str(inf):
            ap_inf['Frequency'] = str(inf[30:-1].decode("utf-8"))
        elif 'Bit Rates' in str(inf):
            ap_inf['Bit Rate'] = str(inf[30:-1].decode("utf-8"))
        elif 'Signal' in str(inf):
            ap_inf['Signal Level'] = (int(str(inf.decode("utf-8")).strip().split("=")[2].split("/")[0]))
            aps_data[ap_essid] = ap_inf.copy()

    return aps_data[ap_selected]['Signal Level']
    
def traffic():
    op = os.popen("vnstat -5 | tail -n 2 | head -n 1").readline()
    traffic_rate = float(op.strip().split("|")[3].strip().split(' ')[0])
    rate_unit = op.strip().split("|")[3].strip().split(' ')[1][0]
    if (rate_unit == 'k'):
        traffic_rate = traffic_rate / 1000
    elif (rate_unit == 'b'):
        traffic_rate = traffic_rate / pow(10,6)
    return traffic_rate

def bandwidth():
    st = speedtest.Speedtest()
    bw = st.download() / pow(10, 6)
    return bw

def hclass(hr):
    return "h" + str((hr // 3) + 1)

def ssclass(ss):
    if ss < 25:
        ss_class = "ss1"
    elif ss >= 25 and ss < 50:
        ss_class = "ss2"
    elif ss >= 50 and ss < 75:
        ss_class = "ss3"
    else:
        ss_class = "ss4"
    return ss_class

def fetch_bw(candidate_aps):
    mydb = mysql.connector.connect(
        host="",
        user="shashwat",
        password="shashwat",
        database="ap_selection"
        )
    mycursor = mydb.cursor()
    now_hr = datetime.now().hour
    hr_class = hclass(now_hr)
    min_rows  = 10
    avg_bw = -1
    for ap in candidate_aps:
        ss_class = ssclass(candidate_aps[ap]['ss'])
        sql_cmd = "select count(bw) from "+ ap +" where hr_class = '"+ hr_class +"' and ss_class ='"+ ss_class +"'"
        mycursor.execute(sql_cmd)
        rows = mycursor.fetchall()[0][0]
        if rows < min_rows:
            sql_cmd = "select count(bw) from "+ ap +" where hr_class = '"+ hr_class +"'"
            mycursor.execute(sql_cmd)
            rows = mycursor.fetchall()[0][0]
            if not rows:
                sql_cmd = "select avg(bw) from "+ap
            else:
                sql_cmd = "select avg(bw) from "+ap+" where hr_class = '"+ hr_class +"'"
        else:
            sql_cmd = "select avg(bw) from "+ ap +" where hr_class = '"+ hr_class +"' and ss_class ='"+ ss_class +"'"
        mycursor.execute(sql_cmd)
        avg_bw = mycursor.fetchall()[0][0]
        candidate_aps[ap]['bw'] = avg_bw
    mydb.close()
    

def decison_maker():
    aps = fetch_aps_data()
    #min_rows  = 10
    candidate_aps = {}
    with open("ap_conf.json") as f:
        l_conn_data = json.load(f)
    for ap in aps:
        if ap in l_conn_data:
            candidate_aps[ap] = {"bw" : 0, "bit_rate" : aps[ap]['Bit Rate'], "ss" : aps[ap]['Signal Level'], "last_conn":l_conn_data[ap]}
    #find approx b/w of candidate aps
    fetch_bw(candidate_aps)
    candidate_aps = {k: v for k, v in sorted(candidate_aps.items(), key=lambda item: (item[1]['bw'],item[1]['last_conn'],item[1]["bit_rate"]), reverse = True)}
    return candidate_aps

def data_dump(ap, monitor_data, close):
    now_tm_stmp= datetime.now().strftime("%Y/%m/%d %H:%M")
    new_ap = False
    file_handle = open('ap_conf.json', "a+")
    file_handle.close()
    ap_file = ap + ".csv"
    if (not os.path.getsize('ap_conf.json')):
            new_ap = True
            with open('ap_conf.json', 'a+') as file:            
                data = {'last_conn_timestamp':now_tm_stmp, ap:now_tm_stmp}
                json.dump(data,file,indent=4)
    else:
            #with open(file) as f:
            with open('ap_conf.json') as file:
                inf = json.load(file)
                if ap not in inf.keys():
                    new_ap = True  
                inf[ap] = now_tm_stmp
                with open('ap_conf.json',"w") as file:
                    json.dump(inf,file,indent=4)
    #if there is some data first dump it
    if len(monitor_data):
        mydb = mysql.connector.connect(
        host="",
        user="shashwat",
        password="shashwat",
        database="ap_selection"
        )   

        print(mydb) 
        mycursor = mydb.cursor()
        if new_ap:
            cmd = "create table "+ ap + " (sr_no int not null AUTO_INCREMENT primary key,Date date,hr_class varchar(5),ss_class varchar(5), traffic_rate float, bw float)"
            mycursor.execute(cmd)
        
        cmd = "insert into "+ap+" (Date, hr_class, ss_class,traffic_rate, bw) values (%s,%s,%s,%s,%s)"
        val =[]
        for inf in monitor_data:
            val.append((inf[0],inf[1],inf[2],round(inf[3],2),round(inf[4],2)))
        mycursor.executemany(cmd, val)
      
        mydb.commit()
        print(" rows are successfully inserted.")
        mydb.close()
        with open(ap_file, 'a+') as file:
                writer = csv.writer(file)
                writer.writerows(monitor_data)
    
    if (close and len(ap)):
        
        if (not os.path.getsize('ap_conf.json')):
            with open('ap_conf.json', 'a+') as file:            
                data = {'last_conn_timestamp':now_tm_stmp, ap:now_tm_stmp}
                json.dump(data,file,indent=4)
    
        else:
            with open('ap_conf.json') as file:
                inf = json.load(file)
                inf[ap] = now_tm_stmp
                inf['last_conn_timestamp'] = now_tm_stmp
                with open('ap_conf.json',"w") as file:
                    json.dump(inf,file,indent=4)
    
def wifi_connect(ap_name,ap_pswd):
    sh_cmd = "nmcli dev wifi connect " + ap_name + " password " + ap_pswd
    shell_cmd = subprocess.Popen(sh_cmd.split(" "),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    op,err = shell_cmd.communicate()
    print("op = " + str(op.decode("utf-8")))
    if len(err):
        print("Error:" + str(err.decode("utf-8")))
        return 0        
    else:
        print("Succesfully connected to "+ ap_name)
        return 1
        #monitor(ap_name,recm_aps)
    
def monitor(ap,recm_aps):
    
    cur_time = datetime.now()
    cur_hour = cur_time.hour
    cur_min = cur_time.minute
    cur_date = cur_time.strftime("%Y/%m/%d")
    
    if (os.path.getsize("ap_conf.json")):
        l_conn_data = {}
        with open("ap_conf.json") as f:
            l_conn_data = json.load(f)
        
        last_conn_timestamp = l_conn_data['last_conn_timestamp']   
        most_recent_dt = last_conn_timestamp.strip().split(" ")[0]
        most_recent = last_conn_timestamp.strip().split(" ")[1]
        most_recent_hr = int(most_recent.split(':')[0])
        most_recent_min = int(most_recent.split(':')[1])
        
        
        
        if ((most_recent_dt == cur_date) and 
            (cur_hour == most_recent_hr) and 
            ((cur_min - most_recent_min) <= 10)):
            time.sleep(300)
    
    
    hr_class = hclass(cur_hour)
    ap_file = ap + ".csv"
    monitor_data = []
    low_count = 0
    predicted_cur_ap_bw = 0
    print(recm_aps)
    max_bw_val = 0
    if len(recm_aps):  
        max_bw_val = recm_aps[list(recm_aps.keys())[0]]['bw']
    print("max_bw:"+str(max_bw_val))
    ch = 'y'
    if len(recm_aps):
        if ap in recm_aps:
            predicted_cur_ap_bw = recm_aps[ap]['bw']
        
    def signal_handler(sig, frame):
        print('terminating...')
        data_dump(ap, monitor_data, 1)    
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    
    file_handle = open(ap_file, "a+")
    file_handle.close()
    while True:
        #bw = bandwidth()
        #print(format(bw,'.2f'))
        que = queue.Queue()
        t1 = threading.Thread(target=lambda q,arg1: q.put(bandwidth()), args=(que, 1)) 
        t2 = threading.Thread(target=lambda q,arg1: q.put(traffic()), args=(que,2)) 
        
        t1.start() 
        t2.start() 

        t1.join() 
        t2.join()
        
        tr_rate = round(que.get(),2)
        bw = round(que.get(),2)
        ss = sig_str(ap)
        ss_class = ""
        
        print("b/w:" + str(bw))
        print("traffic_rate:" + str(tr_rate))
        print("Signal Strength:" + str(ss))
        
        if ss < 25:
            ss_class = "ss1"
        elif ss >= 25 and ss < 50:
            ss_class = "ss2"
        elif ss >= 50 and ss < 75:
            ss_class = "ss3"
        else:
            ss_class = "ss4"
            
        cur_data = [cur_date, hr_class, ss_class, tr_rate, bw]
        if len(monitor_data) == 0:
            monitor_data.append(cur_data)
        else:
            for inf in monitor_data:
                if inf[2] == cur_data[2]:
                    inf[3] = (inf[3] + cur_data[3]) / 2
                    inf[4] = (inf[4] + cur_data[4]) / 2
                    break
            else:
                monitor_data.append(cur_data)
        
        
                        
        now = datetime.now()
        cur_hr = now.hour
        cur_hr_class = hclass(cur_hr)
        if  (hr_class != cur_hr_class) or ( cur_hr == 0):
            
            cur_hour = cur_hr
            hr_class = cur_hr_class
            
            #dump to database
            data_dump(ap, monitor_data, 0)
            with open(ap_file, 'a+') as file:
                writer = csv.writer(file)
                writer.writerows(monitor_data)
            
                        
            if (cur_hr == 0):        
                cur_date = now.strftime("%Y/%m/%d")
            
            monitor_data = []
            
        if ch == 'y' and len(recm_aps) and bw < max_bw_val:
            if low_count < 2:
                low_count += 1
            else:
                print("bandwidth is less than expected.")
                print("You can switch to following aps:")
                for i in recm_aps:
                    print(i +" "+ str(recm_aps[i]['bw'])+" "+str(recm_aps[i]['ss'])+" "+str(recm_aps[i]['bit_rate']))
                print("Enter Ap name if interested, else - N")
                ch = input()
                if ch != 'N':
                    data_dump(ap, monitor_data, 0)
                    new_ap = ch
                    with open("ap_pswd.json") as f:
                        pswds = json.load(f)
                    if new_ap in pswds:
                        ap_psw = pswds[new_ap]
                    else:
                        print("Enter pswd:")
                        ap_psw = input()
                    ######################################
                    
                    if not wifi_connect(new_ap, ap_psw):
                        if wifi_connect(ap, pswds[ap]):
                            if not wifi_connect(new_ap, ap_psw):
                                print("Unable to connect to " + new_ap +", Manually switch to "+new_ap)
                            else:
                               ap = new_ap
                               low_count = 0 
        else:
            if low_count and len(recm_aps) and bw >= max_bw_val:
                low_count = 0
            
                    
        time.sleep(300)
    
  

if __name__ == "__main__":
    candidate_fingerprints = {}
    recm_aps = {}
    if loc_rec():
      #use legacy approach  
      print("################################")
      print(candidate_fingerprints)
      print_aps_data()
    else:
        print("No need to use legacy approach")
        aps_rec = decison_maker()
        print("Available APS:")
        print_aps_data()
        print("\nrecommended APS:")
        print(aps_rec)
        recm_aps = aps_rec
    
    with open("ap_pswd.json") as f:
        pswds = json.load(f)
        
    print("Enter AP name:")
    ap_name = input()
    
    if ap_name in pswds:
        ap_pswd = pswds[ap_name]
    else:
        print("Enter password:")
        ap_pswd = input()
    
    if(wifi_connect(ap_name, ap_pswd)):
        monitor(ap_name,recm_aps)
    else:
        print("Error in connecting to ap:" + ap_name)
    
        
        
    
    
    