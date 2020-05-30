import os
import pandas as pd
import re
import datetime
import json

LOGS_DIR = '/var/log/'
WAN_IF = 'enp1s0'
WAN_IP = '1.2.3.4'

ufw_logs = [file for file  in os.listdir(LOGS_DIR) if re.match('ufw', file)]
print(ufw_logs)

for file in ufw_logs:
    lines = []
    with open(LOGS_DIR+file, 'rt') as lf:
        lines.extend([re.search(r'(.*) kernel\: .+? \[UFW BLOCK\] (.+)$', line.strip('\n').strip(' ')).groups() \
        for line in lf.readlines() if ( bool(re.search('[UFW BLOCK]',line)) & bool(re.search('DST='+WAN_IP,line)) \
        & bool(re.search('IN='+WAN_IF, line)) )])

month_dict={'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}

dict_list = []
for datepart, valuepart in lines:
    dic = dict([tuple(val.split('=') if re.search('=',val) else [val,""]) for val in valuepart.split(' ')])
    dateList = datepart.split(' ')[:3]
    timeList = dateList[2].split(':')
    dic.update({'datetime':datetime.datetime(year=2020, month=month_dict[dateList[0]], \
            day=int(dateList[1]), hour=int(timeList[0]), minute=int(timeList[1]), second=int(timeList[2]) )})
    dict_list.append(dic)

df = pd.json_normalize(dict_list)

#df.to_excel('ufw_log.xlsx', index=None)

df_summary = df.groupby(['SRC'])['datetime'].agg(['min','max','count']).rename(columns={'min':'first','max':'last'})

print(f"count of IPs with count gt2: {len(df_summary[df_summary['count'] > 2])}")

#df_summary.to_pickle('ufw_ip_summary_'+str(int(datetime.datetime.utcnow().timestamp()))+'.pkl.gz')

uniq_ips = list(set([line['SRC'] for line in dict_list]))
print("uniq IPs count:", len(uniq_ips))
#with open('ip_list'+str(int(datetime.datetime.utcnow().timestamp()))+'.json', 'wt+') as f:
#    f.write(json.dumps(uniq_ips))
