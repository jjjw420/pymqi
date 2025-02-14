# See discussion and more examples at http://packages.python.org/pymqi/examples.html
# or in doc/sphinx/examples.rst in the source distribution.

import logging

import pymqi

logging.basicConfig(level=logging.INFO)

queue_manager = "QM01"
channel = "SVRCONN.1"
host = "192.168.1.135"
port = "1434"
queue_name = "TEST.1"
message = "Hello from Python!"
property_name = "Propertie_1"
conn_info = "%s(%s)" % (host, port)

qmgr = pymqi.connect(queue_manager, channel, conn_info)

put_msg_h = pymqi.MessageHandle(qmgr)
put_msg_h.properties.set(property_name, message) #default type is CMQC.MQTYPE_STRING

pmo = pymqi.PMO(Version=pymqi.CMQC.MQPMO_VERSION_3) #PMO v3 is minimal for using propeties
pmo.OriginalMsgHandle = put_msg_h.msg_handle

put_md = pymqi.MD(Version=pymqi.CMQC.MQMD_CURRENT_VERSION)

put_queue = pymqi.Queue(qmgr, queue_name)
put_queue.put(b'', put_md, pmo)

#getting message with propertie
get_msg_h = pymqi.MessageHandle(qmgr)

gmo = pymqi.GMO(Version=pymqi.CMQC.MQGMO_CURRENT_VERSION)
gmo.Options = pymqi.CMQC.MQGMO_PROPERTIES_IN_HANDLE
gmo.MsgHandle = get_msg_h.msg_handle

get_md = pymqi.MD()
get_queue = pymqi.Queue(qmgr, queue_name)
message_body = get_queue.get(None, get_md, gmo)

property_value = get_msg_h.properties.get(property_name)
logging.info("Message received. Propertie name: `%s`, propertie value: `%s`" % (property_name, property_value))

put_queue.close()
get_queue.close()
qmgr.disconnect()
