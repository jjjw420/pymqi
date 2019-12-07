'''
Jul 2016
@author: Hannes Wagener

This includes most of the IBM MQ PCF structures that are not currently defined in pymqi. 
These should probably be in pymqi (for completeness) but to handle these structures and run 
PCF commands on all platforms the MQOpts class had to be extended to be numeric encoding aware.   

This is required as MQ PCF messages should be sent using the numeric encoding 
of target queue manager.  So to send PCF messages from Windows or Linux to a Z/OS queue manager 
the binary numerics in all the PCF headers should be big-endian.

Codepage conversion(from EBCDIC to ASCII) is also required in both directions in order to send 
and receive PCF messages to a Z/OS queue manager.

Along with the PCF headers the "PCFCommand" and "PCFCommmandResponse" helper classes were 
created to facilitate the packing, unpacking and sending/receiving of the PCF messages.  

PCF Array parameter types have "add" methods to aid in contructing the headers.

Use is similar to using PCFexecute.  

1.)  Create a "PCFCommand" instance.   

Specify the codepage of the remote system and it's numeric encoding.  
If ccsid or encoding is not set the MQ defaults will be used.

 pcf_c = PCFCommand(qmgr, ccsid=819, encoding=546, convert=False, zos=False)

If sending PCF messages to a ZOS queue manager specify zos=True and convert=True/False depending on whether text should be converted from EBCDIC to ASCII.

eg.

 pcf_c = PCFCommand(qmgr, ccsid=37, encoding=785, convert=True, zos=True)

 If zos=True and no ccsid or encoding is specified then ccisd=37, encoding=785 and convert=True is assumed.

 If the ccisd or encoding is unknown - then set to zero. All that really applies is whether it's small or big endian.  
 
 If your "execute_command" requests fails with messages like "PYMQI Error: Unsupported parameter type. Type: 67108864" - then change your encoding to the opposite of what you are using (eg.  use bigendian instead of small, small instead of big).  
 Check the default encoding of your queue manager to be sure.
 See the "notes" section below for a brief overview of what to use on which platform.

2.)  execute any type of PCF command, specifying specific object attributes using the "execute_command" method.  
Attributes can be passed as an array of tuples or an array of single key/value dictionaries. 

For instance...

Run a MQSC command (MQCMD_ESCAPE is not implemented on ZOS):
 
    print(pcf_c.execute_command(pymqi.CMQCFC.MQCMD_ESCAPE, [(pymqi.CMQCFC.MQIACF_ESCAPE_TYPE, pymqi.CMQCFC.MQET_MQSC), (pymqi.CMQCFC.MQCACF_ESCAPE_TEXT, "DIS QL(*)")]))

Inquire queue manager:

    pcf_resp = pcf_c.execute_command(pymqi.CMQCFC.MQCMD_INQUIRE_Q_MGR, [(pymqi.CMQCFC.MQIACF_Q_MGR_ATTRS: [pymqi.CMQC.MQCA_ALTERATION_DATE])])
    print("Comp code:", pcf_resp.comp_code, " Reason code:", pcf_resp.reason_code)
    print("Alterration date is: " + str(pcf_resp.parms[0][pymqi.CMQC.MQCA_ALTERATION_DATE]))
    

Create a queue:

    create_q_parms = [(pymqi.CMQC.MQCA_Q_NAME, b"PYMQI.PCF.TEST.QUEUE"), (pymqi.CMQC.MQIA_Q_TYPE, pymqi.CMQC.MQQT_LOCAL), (pymqi.CMQC.MQIA_MAX_Q_DEPTH, 10), ]
    pcf_r = pcf_c.execute_command(pymqi.CMQCFC.MQCMD_CREATE_Q, create_q_parms)
    print("Comp code:", pcf_r.comp_code, " Reason code:", pcf_r.reason_code)

Inquire queues:

    pcf_r = pcf_c.execute_command(pymqi.CMQCFC.MQCMD_INQUIRE_Q, [(pymqi.CMQC.MQCA_Q_NAME, b"SYSTEM.DEFAULT.*"), (pymqi.CMQC.MQIA_Q_TYPE, pymqi.CMQC.MQQT_LOCAL), (pymqi.CMQCFC.MQIACF_Q_ATTRS, [pymqi.CMQC.MQCA_Q_NAME,pymqi.CMQC.MQIA_Q_TYPE,pymqi.CMQC.MQIA_MAX_Q_DEPTH])])
    print("Comp code:", pcf_r.comp_code, " Reason code:", pcf_r.reason_code)
    for q in pcf_r.parms:
        print(q)

3.)  Helper functions have been added for the common pcf commands.

a.) Inquire queue

Inquire a local queue returning it's name and current depth:

    q_resps = pcf_c.inquire_q(str("SYSTEM.DEFAULT.*"), parms=[{pymqi.CMQC.MQIA_Q_TYPE: pymqi.CMQC.MQQT_LOCAL}], q_attrs=[pymqi.CMQC.MQCA_Q_NAME, pymqi.CMQC.MQIA_CURRENT_Q_DEPTH], stringify_keys=True)
    for q in q_resps:
        print(q)

b.)  Inquire queue Manager
Inquire the alteration date of the queue manager.

    qm_resp = pcf_c.inquire_qmgr(qmgr_attrs=[pymqi.CMQC.MQCA_ALTERATION_DATE], stringify_keys=False)
    print(qm_resp[pymqi.CMQC.MQCA_ALTERATION_DATE])

c.) Run MQSC command.

    pcf_c.mqsc_command("DIS QL(SYSTEM.DEFAULT.LOCAL.QUEUE) ALL") 

If zos the zos_mqsc_command method is called to send MQSC commands to the queue manager.
 

NOTES:
- If running the script on the same platform as the queue manager then there should be no need 
to set the ccsid or encoding unless the queue manager defaults were changed.  

- Common "default" codepages and encodings for queue managers(see the MQOptsWithEncoding class for all big endian encodings):
    # Windows:  Small endian(MQENC_NATIVE) encoding, ASCII codepage.  encoding=546, ccsid=437
    # Linux:  Small endian(MQENC_NATIVE) encoding, Unix ASCII codepage.  encoding=546, ccsid=819
    # AIX: Big endian, Unix ASCII code page.  encoding=785, ccsid=819
    # Z/OS: Big endian, EBCDIC code page.  encoding=785, ccsid=37

-  Z/OS does not support the "MQCMD_ESCAPE" command.  MQSC commands on Z/OS is sent directly to the command queue using MQFMT_COMMAND_1.  Hence the custom zos mqsc method.


'''
from __future__ import print_function

import pymqi
import struct
import binascii
import re
import argparse
import sys

class MQOptsWithEncoding(pymqi.MQOpts):
    """
    MQOpt class that can handle numeric encoding.  
    Encoding needs to be set for big-endian systems like Z/OS."""
    
    big_endian_encodings = [#1
                            pymqi.CMQC.MQENC_INTEGER_NORMAL,
                            #16
                            pymqi.CMQC.MQENC_DECIMAL_NORMAL,
                            #256
                            pymqi.CMQC.MQENC_FLOAT_IEEE_NORMAL,
                            #768
                            pymqi.CMQC.MQENC_FLOAT_S390,
                            #17
                            pymqi.CMQC.MQENC_INTEGER_NORMAL +
                            pymqi.CMQC.MQENC_DECIMAL_NORMAL,
                            #257
                            pymqi.CMQC.MQENC_INTEGER_NORMAL +
                            pymqi.CMQC.MQENC_FLOAT_IEEE_NORMAL,
                            #272
                            pymqi.CMQC.MQENC_DECIMAL_NORMAL +
                            pymqi.CMQC.MQENC_FLOAT_IEEE_NORMAL,
                            #273
                            pymqi.CMQC.MQENC_INTEGER_NORMAL +
                            pymqi.CMQC.MQENC_DECIMAL_NORMAL +
                            pymqi.CMQC.MQENC_FLOAT_IEEE_NORMAL,
                            #785
                            pymqi.CMQC.MQENC_INTEGER_NORMAL +
                            pymqi.CMQC.MQENC_DECIMAL_NORMAL +
                            pymqi.CMQC.MQENC_FLOAT_S390]
    
    def pack(self, encoding=None):
        """pack(encoding)

        Override pack in order to set correct numeric encoding in the format."""
        if encoding is not None:
            if encoding in self.big_endian_encodings:
                self._MQOpts__list[0][2] = ">" + self._MQOpts__list[0][2]
                saved_values = self.get()
                #apply the new opts
                pymqi.MQOpts.__init__(*(self, tuple(self._MQOpts__list)))
                #set from saved values
                self.set(**saved_values)
        
        return pymqi.MQOpts.pack(self)
    
    def unpack(self, buff, encoding=None):
        """unpack(buff, encoding)
        
        Unpack a buffer taking the encoding into account."""
        
        if encoding in self.big_endian_encodings:
            self._MQOpts__list[0][2] = ">" + self._MQOpts__list[0][2]
            
        pymqi.MQOpts.__init__(*(self, tuple(self._MQOpts__list)))
        pymqi.MQOpts.unpack(self, buff)
  
        
class CFH(MQOptsWithEncoding):
    """CFH(**kw)

    Construct a CFH Structure with default values as per MQI. The
    default values may be overridden by the optional keyword arguments
    'kw'."""

    def __init__(self, **kw):
        pymqi.MQOpts.__init__(*(self, (
            ['Type', pymqi.CMQCFC.MQCFT_COMMAND, pymqi.MQLONG_TYPE],
            ['StrucLength', pymqi.CMQCFC.MQCFH_STRUC_LENGTH, pymqi.MQLONG_TYPE],
            ['Version', pymqi.CMQCFC.MQCFH_CURRENT_VERSION, pymqi.MQLONG_TYPE],
            ['Command', pymqi.CMQCFC.MQCMD_NONE, pymqi.MQLONG_TYPE],
            ['MsgSeqNumber', 1, pymqi.MQLONG_TYPE],
            ['Control', pymqi.CMQCFC.MQCFC_LAST,pymqi.MQLONG_TYPE],
            ['CompCode', pymqi.CMQC.MQCC_OK, pymqi.MQLONG_TYPE],
            ['Reason', pymqi.CMQC.MQRC_NONE, pymqi.MQLONG_TYPE],
            ['ParameterCount', 0, pymqi.MQLONG_TYPE],
            )), **kw)

cfh = CFH

class CFBS(MQOptsWithEncoding):
    """CFBS(**kw)

    Construct a CFBS Structure with default values as per MQI. The
    default values may be overridden by the optional keyword arguments
    'kw'."""

    def __init__(self, **kw):
        pymqi.MQOpts.__init__(*(self, (
            ['Type', pymqi.CMQCFC.MQCFT_BYTE_STRING, pymqi.MQLONG_TYPE],
            ['StrucLength', pymqi.CMQCFC.MQCFBS_STRUC_LENGTH_FIXED, pymqi.MQLONG_TYPE],
            ['Parameter', 0, pymqi.MQLONG_TYPE],
            ['StringLength', 0, pymqi.MQLONG_TYPE]
            #['String', pymqi.CMQCFC.MQCFC_LAST,'1s']
            )), **kw)
        
    def unpack(self, buff, encoding=None):
        """unpack(buff, encoding)
        
        Unpack a buffer into a CFBS struct taking the encoding into account."""
        
        if encoding in self.big_endian_encodings:
            self._MQOpts__list[0][2] = ">" + self._MQOpts__list[0][2]
                
        pymqi.MQOpts.__init__(*(self, tuple(self._MQOpts__list)))
        pymqi.MQOpts.unpack(self, buff[:pymqi.CMQCFC.MQCFBS_STRUC_LENGTH_FIXED])
        
        string_value = buff[pymqi.CMQCFC.MQCFBS_STRUC_LENGTH_FIXED:]
        if self["StringLength"] == 0:
            self["StringLength"] = len(string_value)
        else:
            string_value = buff[pymqi.CMQCFC.MQCFBS_STRUC_LENGTH_FIXED:pymqi.CMQCFC.MQCFBS_STRUC_LENGTH_FIXED + self["StringLength"]]
        
        self.opts = self._MQOpts__list + (["String", string_value, "%is" % len(string_value)], )
        self["StrucLength"] = pymqi.CMQCFC.MQCFBS_STRUC_LENGTH_FIXED +  len(string_value)
        #save the current values
        saved_values = self.get()
        #apply the new opts
        pymqi.MQOpts.__init__(*(self, tuple(self.opts)))
        #set from saved values
        self.set(**saved_values)
cfbs = CFBS        
        
class CFBF(MQOptsWithEncoding):
    """CFBF(**kw)

    Construct a CFBF Structure with default values as per MQI. The
    default values may be overridden by the optional keyword arguments
    'kw'."""

    def __init__(self, **kw):
        pymqi.MQOpts.__init__(*(self, (
            ['Type', pymqi.CMQCFC.MQCFT_BYTE_STRING_FILTER, pymqi.MQLONG_TYPE],
            ['StrucLength', pymqi.CMQCFC.MQCFBF_STRUC_LENGTH_FIXED, pymqi.MQLONG_TYPE],
            ['Parameter', 0, pymqi.MQLONG_TYPE],
            ['Operator', 0, pymqi.MQLONG_TYPE],
            ['FilterValueLength', 0, pymqi.MQLONG_TYPE]
            #['FilterValue', '','1s']
            )), **kw)        
cfbf = CFBF

class CFGR(MQOptsWithEncoding):
    """CFGR(**kw)

    Construct a CFGR Structure with default values as per MQI. The
    default values may be overridden by the optional keyword arguments
    'kw'."""

    def __init__(self, **kw):
        pymqi.MQOpts.__init__(*(self, (
            ['Type', pymqi.CMQCFC.MQCFT_GROUP, pymqi.MQLONG_TYPE],
            ['StrucLength', pymqi.CMQCFC.MQCFGR_STRUC_LENGTH, pymqi.MQLONG_TYPE],
            ['Parameter', 0, pymqi.MQLONG_TYPE],
            ['ParameterCount', 0, pymqi.MQLONG_TYPE]
            )), **kw)       

cfgr = CFGR
        
class CFIF(MQOptsWithEncoding):
    """CFIF(**kw)

    Construct a cfif Structure with default values as per MQI. The
    default values may be overridden by the optional keyword arguments
    'kw'."""

    def __init__(self, **kw):
        pymqi.MQOpts.__init__(*(self, (
            ['Type', pymqi.CMQCFC.MQCFT_INTEGER_FILTER, pymqi.MQLONG_TYPE],
            ['StrucLength', pymqi.CMQCFC.MQCFBF_STRUC_LENGTH_FIXED, pymqi.MQLONG_TYPE],
            ['Parameter', 0, pymqi.MQLONG_TYPE],
            ['Operator', 0, pymqi.MQLONG_TYPE],
            ['FilterValue', 0,pymqi.MQLONG_TYPE]
            )), **kw)  

cfif = CFIF       
        
class CFIN(MQOptsWithEncoding):
    """CFIN(**kw)

    Construct a cfin Structure with default values as per MQI. The
    default values may be overridden by the optional keyword arguments
    'kw'."""

    def __init__(self, **kw):
        pymqi.MQOpts.__init__(*(self, (
            ['Type', pymqi.CMQCFC.MQCFT_INTEGER, pymqi.MQLONG_TYPE],
            ['StrucLength', pymqi.CMQCFC.MQCFIN_STRUC_LENGTH, pymqi.MQLONG_TYPE],
            ['Parameter', 0, pymqi.MQLONG_TYPE],
            ['Value', 0,pymqi.MQLONG_TYPE]
            )), **kw)  

cfin = CFIN
        
class CFIL(MQOptsWithEncoding):
    """CFIL(**kw)

    Construct a CFIL Structure with default values as per MQI. The
    default values may be overridden by the optional keyword arguments
    'kw'."""
    
    integer_list = []
    def __init__(self, **kw):
        self.integer_list = []
        pymqi.MQOpts.__init__(*(self, (
            ['Type', pymqi.CMQCFC.MQCFT_INTEGER_LIST, pymqi.MQLONG_TYPE],
            ['StrucLength', pymqi.CMQCFC.MQCFIL_STRUC_LENGTH_FIXED, pymqi.MQLONG_TYPE],
            ['Parameter', 0, pymqi.MQLONG_TYPE],
            ['Count', 0, pymqi.MQLONG_TYPE],
            )), **kw) 

    
    def add_integer(self, value, encoding=None):
        """add_integer(value)
        
        Add an integer to the list and update the structure accordingly."""
        
        self.integer_list.append(value)
        
    
        self["Count"] = self["Count"] + 1
        self["StrucLength"] =  pymqi.CMQCFC.MQCFIL_STRUC_LENGTH_FIXED + (struct.calcsize(pymqi.MQLONG_TYPE) *  self["Count"])
        
        string_value = ""
        format_str = "i" * len(self.integer_list)
        #for i in self.integer_list:

        if encoding in self.big_endian_encodings and not self._MQOpts__list[0][2].startswith(">"):
            string_value = struct.pack(">" + format_str, *self.integer_list)
        else:
            string_value = struct.pack(format_str, *self.integer_list)
        
        if hasattr(self, "IntegerList"):
            self["IntegerList"] = string_value
            self.opts = self._MQOpts__list[:-1] + (["IntegerList", string_value, "%is" % len(string_value)], )
        else:
            self.opts = self._MQOpts__list + (["IntegerList", string_value, "%is" % len(string_value)], )
             
        saved_values = self.get()
       
        #apply the new opts
        pymqi.MQOpts.__init__(*(self, tuple(self.opts)))
        #set from saved values
        self.set(**saved_values)               
            
    def unpack(self, buff, encoding=None):
        """unpack(buff, encoding)
        
        Unpack a buffer into the CFIL structure."""
            
        if encoding in self.big_endian_encodings:
            self._MQOpts__list[0][2] = ">" + self._MQOpts__list[0][2]
                
        pymqi.MQOpts.__init__(*(self, tuple(self._MQOpts__list)))
        pymqi.MQOpts.unpack(self, buff[:pymqi.CMQCFC.MQCFIL_STRUC_LENGTH_FIXED])
        
        string_value = buff[pymqi.CMQCFC.MQCFIL_STRUC_LENGTH_FIXED:]
       
        self.opts = self._MQOpts__list + (["IntegerList", string_value, "%is" % len(string_value)], )
        if self["StrucLength"] == pymqi.CMQCFC.MQCFST_STRUC_LENGTH_FIXED or self["StrucLength"] == 0: 
            self["StrucLength"] = pymqi.CMQCFC.MQCFST_STRUC_LENGTH_FIXED +  len(string_value)
        
        int_buf = string_value    
        for _i in range(self["Count"]):
            self.integer_list.append(struct.unpack(pymqi.MQLONG_TYPE, int_buf[:4]))
            int_buf = int_buf[4:]
        #save the current values
        saved_values = self.get()
        #apply the new opts
        pymqi.MQOpts.__init__(*(self, tuple(self.opts)))
        #set from saved values
        self.set(**saved_values)                 

cfil = CFIL         

class CFSF(MQOptsWithEncoding):
    """CFSF(**kw)

    Construct a CFSF Structure with default values as per MQI. The
    default values may be overridden by the optional keyword arguments
    'kw'."""

    def __init__(self, **kw):
        pymqi.MQOpts.__init__(*(self, (
            ['Type', pymqi.CMQCFC.MQCFT_STRING_FILTER, pymqi.MQLONG_TYPE],
            ['StrucLength', pymqi.CMQCFC.MQCFSF_STRUC_LENGTH_FIXED, pymqi.MQLONG_TYPE],
            ['Parameter', 0, pymqi.MQLONG_TYPE],
            ['Operator', 0, pymqi.MQLONG_TYPE],
            ['CodedCharSetId', pymqi.CMQC.MQCCSI_DEFAULT, pymqi.MQLONG_TYPE],
            ['FilterValueLength', 0, pymqi.MQLONG_TYPE]
            #['FilterValue', '','1s']
            )), **kw)     
            
    def unpack(self, buff, encoding=None):
        """unpack(buff, encoding)
        
        Unpack a buffer into the CFSF structure."""
      
        if encoding in self.big_endian_encodings:
            self._MQOpts__list[0][2] = ">" + self._MQOpts__list[0][2]
                
        pymqi.MQOpts.__init__(*(self, tuple(self._MQOpts__list)))
        pymqi.MQOpts.unpack(self, buff[:pymqi.CMQCFC.MQCFSF_STRUC_LENGTH_FIXED])
        
        string_value = buff[pymqi.CMQCFC.MQCFSF_STRUC_LENGTH_FIXED:pymqi.CMQCFC.MQCFSF_STRUC_LENGTH_FIXED + self["FilterValueLength"]]
        if self["FilterValueLength"] == 0:
            self["FilterValueLength"] = len(string_value)
        else:
            string_value = buff[pymqi.CMQCFC.MQCFSF_STRUC_LENGTH_FIXED:pymqi.CMQCFC.MQCFSF_STRUC_LENGTH_FIXED + self["FilterValueLength"]]
        
        
        self.opts = self._MQOpts__list + (["FilterValue", string_value, "%is" % self["FilterValueLength"]], )
        if self["StrucLength"] == pymqi.CMQCFC.MQCFSF_STRUC_LENGTH_FIXED or self["StrucLength"] == 0:
            self["StrucLength"] = pymqi.CMQCFC.MQCFSF_STRUC_LENGTH_FIXED +  len(string_value)
        #save the current values
        saved_values = self.get()
        #apply the new opts
        pymqi.MQOpts.__init__(*(self, tuple(self.opts)))
        #set from saved values
        self.set(**saved_values)   

cfsf = CFSF

class CFST(MQOptsWithEncoding):
    """CFST(**kw)

    Construct a CFST Structure with default values as per MQI. The
    default values may be overridden by the optional keyword arguments   
    'kw'. 
    """

    def __init__(self, **kw):
        pymqi.MQOpts.__init__(*(self, (
            ['Type', pymqi.CMQCFC.MQCFT_STRING, pymqi.MQLONG_TYPE],
            ['StrucLength', pymqi.CMQCFC.MQCFST_STRUC_LENGTH_FIXED, pymqi.MQLONG_TYPE],
            ['Parameter', 0, pymqi.MQLONG_TYPE],
            ['CodedCharSetId', pymqi.CMQC.MQCCSI_DEFAULT, pymqi.MQLONG_TYPE],
            ['StringLength', 0, pymqi.MQLONG_TYPE]
            #['String', '','1s']
            )), **kw)   
        
    def set_string(self, string_value):
        """set_string(value)
             
        Set the variable length string and update the structure accordingly."""
        #apply(pymqi.MQOpts.__init__, (self, tuple(self._MQOpts__list)), )
        self["StringLength"] = len(string_value)
        
        self.opts = self._MQOpts__list + (["String", string_value, "%is" % self["StringLength"]], )
        if self["StrucLength"] == pymqi.CMQCFC.MQCFST_STRUC_LENGTH_FIXED or self["StrucLength"] == 0: 
            self["StrucLength"] = pymqi.CMQCFC.MQCFST_STRUC_LENGTH_FIXED +  len(string_value)
        #save the current values
        saved_values = self.get()
        #apply the new opts
        pymqi.MQOpts.__init__(*(self, tuple(self.opts)))
        #set from saved values
        self.set(**saved_values)
            
    def unpack(self, buff, encoding=None):
        """unpack(buff, encoding)
        
        Unpack a buffer into the CFST structure."""
   
        if encoding in self.big_endian_encodings:
            self._MQOpts__list[0][2] = ">" + self._MQOpts__list[0][2]
                
        pymqi.MQOpts.__init__(*(self, tuple(self._MQOpts__list)))
        pymqi.MQOpts.unpack(self, buff[:pymqi.CMQCFC.MQCFST_STRUC_LENGTH_FIXED])
        
        string_value = buff[pymqi.CMQCFC.MQCFST_STRUC_LENGTH_FIXED:]
        if self["StringLength"] == 0:
            self["StringLength"] = len(string_value)
        else:
            string_value = buff[pymqi.CMQCFC.MQCFST_STRUC_LENGTH_FIXED:pymqi.CMQCFC.MQCFST_STRUC_LENGTH_FIXED + self["StringLength"]]
        
        self.opts = self._MQOpts__list + (["String", string_value, "%is" % self["StringLength"]], )
        if self["StrucLength"] == pymqi.CMQCFC.MQCFST_STRUC_LENGTH_FIXED or self["StrucLength"] == 0: 
            self["StrucLength"] = pymqi.CMQCFC.MQCFST_STRUC_LENGTH_FIXED +  len(string_value)
        #save the current values
        saved_values = self.get()
        #apply the new opts
        pymqi.MQOpts.__init__(*(self, tuple(self.opts)))
        #set from saved values
        self.set(**saved_values)

cfst = CFST        
                    
class CFSL(MQOptsWithEncoding):
    """CFSL(**kw)

    Construct a CFSL Structure with default values as per MQI. The
    default values may be overridden by the optional keyword arguments
    'kw'."""
    
    string_list = []

    def __init__(self, **kw):
        self.string_list = []
        pymqi.MQOpts.__init__(*(self, (
            ['Type', pymqi.CMQCFC.MQCFT_STRING_LIST, pymqi.MQLONG_TYPE],
            ['StrucLength', pymqi.CMQCFC.MQCFSL_STRUC_LENGTH_FIXED, pymqi.MQLONG_TYPE],
            ['Parameter', 0, pymqi.MQLONG_TYPE],
            ['CodedCharSetId', pymqi.CMQC.MQCCSI_DEFAULT, pymqi.MQLONG_TYPE],
            ['Count', 0, pymqi.MQLONG_TYPE],
            ['StringLength', 0, pymqi.MQLONG_TYPE]
            #['String', '','1s']
            )), **kw)   
  
    def add_string(self, value):
        """add_string(value)
              
        Add a string to the list and update the structure accordingly."""
        self.string_list.append(value)
        if self["StringLength"] == 0:
            self["StringLength"] =  len(value)
        
        self["Count"] = self["Count"] + 1
        self["StrucLength"] =  pymqi.CMQCFC.MQCFSL_STRUC_LENGTH_FIXED + (self["StringLength"] *  self["Count"])
        
        string_value = ""
        for s in self.string_list:
            if len(s) < self["StringLength"]:
                s = s + " " * self["StringLength"] - len(s)
            if len(s) > self["StringLength"]:
                s = s[:self["StringLength" - 1]]
                
            string_value = string_value + s  
            
        if hasattr(self, "StringList"):
            self["StringList"] = string_value
            self.opts = self._MQOpts__list[:-1] + (["StringList", string_value, "%is" % len(string_value)], )
        else:
            self.opts = self._MQOpts__list + (["StringList", string_value, "%is" % len(string_value)], )
             
        saved_values = self.get()
       
        #apply the new opts
        pymqi.MQOpts.__init__(*(self, tuple(self.opts)))
        #set from saved values
        self.set(**saved_values)               

            
    def unpack(self, buff, encoding=None):
        """unpack(buff, encoding)
        
        Unpack a buffer into the CFSL structure."""
          
        if encoding in self.big_endian_encodings:
            self._MQOpts__list[0][2] = ">" + self._MQOpts__list[0][2]
                
        pymqi.MQOpts.__init__(*(self, tuple(self._MQOpts__list)))
        pymqi.MQOpts.unpack(self, buff[:pymqi.CMQCFC.MQCFSL_STRUC_LENGTH_FIXED])
        
        string_value = buff[pymqi.CMQCFC.MQCFSL_STRUC_LENGTH_FIXED:]
        if self["StringLength"] == 0:
            self["StringLength"] = len(string_value)
        else:
            string_value = buff[pymqi.CMQCFC.MQCFSL_STRUC_LENGTH_FIXED:pymqi.CMQCFC.MQCFSL_STRUC_LENGTH_FIXED + self["StringLength"]]
        
        self.opts = self._MQOpts__list + (["StringList", string_value, "%is" % self["StringLength"]], )
        if self["StrucLength"] == pymqi.CMQCFC.MQCFSL_STRUC_LENGTH_FIXED or self["StrucLength"] == 0: 
            self["StrucLength"] = pymqi.CMQCFC.MQCFSL_STRUC_LENGTH_FIXED +  len(string_value)
        #save the current values
        saved_values = self.get()
        #apply the new opts
        pymqi.MQOpts.__init__(*(self, tuple(self.opts)))
        #set from saved values
        self.set(**saved_values)
        
cfsl = CFSL

class PCFCommandResponse(object):
    """PCFCommandResponse(struct_list)
    
    Helper class to PCF command responses. Returned by the PCFCommand.execute_command method."""
   
    def __init__(self, struct_list=[]):
        self._struct_list = struct_list
        #self._parm_structs = []
        self._headers = []
        self._header = None
        self._parms = []
        if len(self._struct_list) > 0:
            for pcf_s in self._struct_list:
                pcf_dict = {}
                for pcf_st in pcf_s:
                    parm_type = pcf_st["Type"]
                    if parm_type == pymqi.CMQCFC.MQCFT_RESPONSE or parm_type == pymqi.CMQCFC.MQCFT_XR_ITEM or parm_type == pymqi.CMQCFC.MQCFT_XR_MSG or parm_type == pymqi.CMQCFC.MQCFT_XR_SUMMARY:
                        self._headers.append(pcf_st)
                        if self._header is None:
                            self._header = pcf_st
                        if parm_type == pymqi.CMQCFC.MQCFT_XR_SUMMARY:
                            break
                    elif parm_type == pymqi.CMQCFC.MQCFT_INTEGER:
                        pcf_dict[pcf_st["Parameter"]] = pcf_st["Value"]
                    elif parm_type == pymqi.CMQCFC.MQCFT_STRING:
                        pcf_dict[pcf_st["Parameter"]] = pcf_st["String"]
                    elif parm_type == pymqi.CMQCFC.MQCFT_INTEGER_LIST:
                        pcf_dict[pcf_st["Parameter"]] = pcf_st["IntegerList"]
                    elif parm_type == pymqi.CMQCFC.MQCFT_STRING_LIST:
                        pcf_dict[pcf_st["Parameter"]] = pcf_st["StringList"]
                    elif parm_type == pymqi.CMQCFC.MQCFT_BYTE_STRING:
                        pcf_dict[pcf_st["Parameter"]] = pcf_st["String"]                        
                    else:
                        print("Response:", pymqi.PYIFError("Unsupported parameter type. Type: {}".format(parm_type)))
                        raise pymqi.PYIFError("Unsupported parameter type. Type: {}".format(parm_type))
                if len(pcf_dict) > 0:        
                    self._parms.append(pcf_dict)
        else:
            raise pymqi.PYIFError("PCF Structure List empty.")
        
    @property
    def struct_list(self):
        return self._struct_list

    # @property
    # def parm_structs(self):
    #     return self._parm_structs
    
    @property
    def parms(self):
        return self._parms
    
    @property
    def header(self):
        return self._header
    
    @property
    def headers(self):
        return self._headers
    
    @property
    def reason_code(self):
        reason_code = None
        if self._header is not None:
            reason_code = self._header["Reason"]
        return reason_code

    @property
    def reason_codes(self):
        reason_codes = []
        for pcf_hdr in self._headers:
            reason_codes.append(pcf_hdr["Reason"])
        return reason_codes
    
    @property
    def comp_code(self):
        comp_code = None
        if self._header is not None:
            comp_code = self._header["CompCode"]
        return comp_code
    
    def stringify_keys(self, parms=None):
        if parms is None:
            parms =  self._parms
        pcf = pymqi.PCFExecute(None)
        str_parms = []
        for s in parms:
            str_parms.append(pcf.stringifyKeys(s))
        
        return str_parms 
    
    def __repr__(self):
        return str(self.stringify_keys())
    
    # def __getitem__(self, key):
    #     """__getitem__(key)

    #     Return the member value associated with key, as in print
    #     obj['Flop']."""

    #     return self.get_pcf_parm(key)

    # def get_pcf_parm(self, key):
    #     """__getitem__(key)

    #     Return the member value associated with key, as in print(obj['Flop']).
    #     self.parms is an array - return only first. """
        
    #     it = None
    #     if self.parms is not None:
    #         if len(self.parms) > 0:
    #             if isinstance(self.parms[0], dict):
    #                 if key in self.parms[0]:
    #                     it = self.parms[0][key]


        return it
    

class PCFCommand(object):
    """PCFCommand(qmgr, ccsid, encoding)
    
    PCFCommand class that handles numeric encoding, variable length pcf strutures and complex pcf bags."""
    
    big_endian_encodings = [pymqi.CMQC.MQENC_INTEGER_NORMAL,
                        pymqi.CMQC.MQENC_DECIMAL_NORMAL,
                        pymqi.CMQC.MQENC_FLOAT_IEEE_NORMAL,
                        pymqi.CMQC.MQENC_FLOAT_S390,
                        #17
                        pymqi.CMQC.MQENC_INTEGER_NORMAL +
                        pymqi.CMQC.MQENC_DECIMAL_NORMAL,
                        #257
                        pymqi.CMQC.MQENC_INTEGER_NORMAL +
                        pymqi.CMQC.MQENC_FLOAT_IEEE_NORMAL,
                        #272
                        pymqi.CMQC.MQENC_DECIMAL_NORMAL +
                        pymqi.CMQC.MQENC_FLOAT_IEEE_NORMAL,
                        #273
                        pymqi.CMQC.MQENC_INTEGER_NORMAL +
                        pymqi.CMQC.MQENC_DECIMAL_NORMAL +
                        pymqi.CMQC.MQENC_FLOAT_IEEE_NORMAL, 
                        #785
                        pymqi.CMQC.MQENC_INTEGER_NORMAL +
                        pymqi.CMQC.MQENC_DECIMAL_NORMAL +
                        pymqi.CMQC.MQENC_FLOAT_S390]


    def __init__(self, qmgr, ccsid=pymqi.CMQC.MQCCSI_DEFAULT, encoding=pymqi.CMQC.MQENC_NATIVE, ccsid_str=None, convert=False, zos=False, command_queue="SYSTEM.ADMIN.COMMAND.QUEUE"):
        self.qmgr = qmgr
        self.zos = zos
        
        if ccsid is None and encoding is None and zos:
            self.ccsid = 37
            self.encoding = 785
            self.convert = True
        else:
            if ccsid is None:
                if zos:
                    self.ccsid = 37
                else:
                    self.ccsid = pymqi.CMQC.MQCCSI_DEFAULT
            else:
                if ccsid == 0:    
                    if zos:
                        self.ccsid = 37
                    else:    
                        self.ccsid = pymqi.CMQC.MQCCSI_DEFAULT
                else:
                    self.ccsid = ccsid
               
            if encoding is None:
                if zos:
                    self.encoding = 785
                else:
                    self.encoding = pymqi.CMQC.MQENC_NATIVE
            else:
                if encoding == 0:
                    if zos:
                        self.encoding = 785
                    else:
                        self.encoding = pymqi.CMQC.MQENC_NATIVE
                else:
                    self.encoding = encoding
            
            if zos:
                self.convert = True
            else:
                self.convert = convert        

            if ccsid_str is None:
                self.ccsid_str = "{:03d}".format(self.ccsid)
            else:
                self.ccsid_str = ccsid_str
        
        if command_queue is None:
            self.command_queue = b"SYSTEM.ADMIN.COMMAND.QUEUE"
        else:
            self.command_queue = command_queue

        #print("self.ccsid:" + str(self.ccsid))
        #print("self.encoding:" + str(self.encoding))
        #print("self.convert:" + str(self.convert))
             
    def pack_bag(self, command=pymqi.CMQCFC.MQCMD_INQUIRE_Q_MGR, parm_list=[]):
        """
        Pack the pcf header and parameters into a buffer. 
        parm_list can include dicts, tuples or pcf class instances.  
        Example parm_list in format:
        [{parm: parm_value}, (parm, parm_value) , cfcn] 
        """
         
        pcf_header = cfh()
        pcf_header["Type"] = pymqi.CMQCFC.MQCFT_COMMAND_XR
        pcf_header["Command"] = command
        pcf_header["Version"] = pymqi.CMQCFC.MQCFH_VERSION_3
        pcf_header["ParameterCount"] = len(parm_list)
        
        out_buf = pcf_header.pack(encoding=self.encoding)
        
        for parm_tpl in parm_list:
            
            if isinstance(parm_tpl, dict):
                if len(parm_tpl) == 0:
                    raise pymqi.PYIFError("PCF Parameter tuple length is zero.")
                
                parm = list(parm_tpl.items())[0][0]
                parm_vals = list(parm_tpl.items())[0][1]
             
                cf_p = None
                #p_type = type(parm_vals)
                #if p_type == type([]):
                if isinstance(parm_vals, list):
                    if len(parm_vals) > 0:
                        #if type(parm_vals[0]) == type(0):
                        if isinstance(parm_vals[0], int):                            
                            # int list
                            cf_p = CFIL()
                            cf_p["Parameter"] = parm
                            for p in parm_vals:
                                cf_p.add_integer(p, encoding=self.encoding)
                        #elif type(parm_vals[0]) == type(""):
                        elif isinstance(parm_vals[0], str) or isinstance(parm_vals[0], bytes):
                            # string
                            cf_p = CFSL()
                            cf_p["CodedCharSetId"] = self.ccsid
                            cf_p["Parameter"] = parm
                            for p in parm_vals:
                                if self.convert:
                                    cf_p.add_string(p.encode(self.ccsid_str))
                                else:
                                    cf_p.add_string(p)
                        else:
                            raise pymqi.PYIFError("Unknown parameter type. Expected int, str or float.")
                else:
                    #if p_type == type(0):
                    if isinstance(parm_vals, int):                        
                        cf_p = CFIN()
                        cf_p["Parameter"] = parm
                        cf_p["Value"] = parm_vals
                    #elif p_type == type(""):
                    elif isinstance(parm_vals, str) or isinstance(parm_vals, bytes):
                        # string
                        #print "parm_vals:", parm_vals
                        #print "self.convert:", self.convert
                        cf_p = CFST()
                        cf_p["CodedCharSetId"] = self.ccsid
                        cf_p["Parameter"] = parm
                        
                        if self.convert:
                            cf_p.set_string(parm_vals.encode(self.ccsid_str))
                        else:
                            cf_p.set_string(parm_vals)
                        
                        #print cf_p
                        
                    else:
                        raise pymqi.PYIFError("Unknown parameter type. Expected int, str or float.")
                
                out_buf = out_buf + cf_p.pack(encoding=self.encoding)
                #print("outbuf:" + str(binascii.hexlify(out_buf)))
            else:
                if isinstance(parm_tpl, tuple):
                    if len(parm_tpl) == 0:
                        raise pymqi.PYIFError("PCF Parameter tuple length is zero.")
            
                    parm = parm_tpl[0]
                    parm_vals = parm_tpl[1]
                 
                    cf_p = None
                    #p_type = type(parm_vals)
                    if isinstance(parm_vals, list):
                        if len(parm_vals) > 0:
                            if isinstance(parm_vals[0], int): 
                                
                                # int list
                                cf_p = CFIL()
                                cf_p["Parameter"] = parm
                                for p in parm_vals:
                                    cf_p.add_integer(p, encoding=self.encoding)
                            elif isinstance(parm_vals[0], str) or isinstance(parm_vals[0], bytes):
                                # string
                                cf_p = CFSL()
                                cf_p["CodedCharSetId"] = self.ccsid
                                cf_p["Parameter"] = parm
                                for p in parm_vals:
                                    cf_p.add_string(p)
                            else:
                                raise pymqi.PYIFError("Unknown parameter type. Expected int, str or float.")
                    else:
                        if isinstance(parm_vals, int):
                            cf_p = CFIN()
                            cf_p["Parameter"] = parm
                            cf_p["Value"] = parm_vals
                        elif isinstance(parm_vals, str) or isinstance(parm_vals, bytes):
                            # string
                            cf_p = CFST()
                            cf_p["CodedCharSetId"] = self.ccsid
                            cf_p["Parameter"] = parm
                            cf_p.set_string(parm_vals)
                        else:
                            raise pymqi.PYIFError("Unknown parameter type. Expected int, str or float.")
                    
                    out_buf = out_buf + cf_p.pack(encoding=self.encoding)
                    #print("outbuf:" + str(binascii.hexlify(out_buf)))
                
                else:
                    if not isinstance(parm_tpl, pymqi.MQOpts):
                        raise pymqi.PYIFError("Unknown parameter type. Expected cfin, cfst, etc.")
                
                #out_buf = out_buf + parm_tpl.pack(encoding=self.encoding)
          
        return out_buf

    
    def unpack_bag(self, buff, convert=False):
        """unpack_bag(buff, encoding)
        
        Unpack a PCF bag from buffer."""
   
        if buff is None:
            return None
        if len(buff) == 0:
            return None

        pcf_dict = {}
        pcf_structs = []
        resp_cfh = cfh()
        resp_cfh.unpack(buff[:36], encoding=self.encoding)
        #print "Unpack - PCF Header:\n", resp_cfh, "----------------"
        pcf_structs.append(resp_cfh)
        
        new_buff =  buff[36:]
        #print "Len:", len(new_buff)
        done = False
        if len(new_buff) == 0:
            done = True
        
        while not done:
            long_format = pymqi.MQLONG_TYPE
            if self.encoding in self.big_endian_encodings:
                long_format = ">" + pymqi.MQLONG_TYPE

            parm_type = struct.unpack(long_format, new_buff[:4])[0]
            struc_len = struct.unpack(long_format, new_buff[4:8])[0]
            
            if parm_type == pymqi.CMQCFC.MQCFT_INTEGER:
                resp_cfin = CFIN()
                resp_cfin.unpack(new_buff[:struc_len], encoding=self.encoding)
                pcf_structs.append(resp_cfin)
                pcf_dict[resp_cfin["Parameter"]] = resp_cfin["Value"]
            elif parm_type == pymqi.CMQCFC.MQCFT_STRING:
                resp_cfst = CFST()
                resp_cfst.unpack(new_buff[:struc_len], encoding=self.encoding)
                if convert:
                    resp_cfst["String"] = resp_cfst["String"].decode(self.ccsid_str)
                    if len(resp_cfst["String"]) != resp_cfst["StringLength"]:
                        print("Converted string length not equal to StringLength. Length: {} Expected Length: {} ".format(len(resp_cfst["String"]), resp_cfst["StringLength"]))
                        raise pymqi.PYIFError("Converted string length not equal to StringLength. Length: {} Expected Length: {} ".format(len(resp_cfst["String"]), resp_cfst["StringLength"]))
                        
                pcf_structs.append(resp_cfst)
                pcf_dict[resp_cfst["Parameter"]] = resp_cfst["String"]
            elif parm_type == pymqi.CMQCFC.MQCFT_INTEGER_LIST:
                resp_cfil = CFIL()
                resp_cfil.unpack(new_buff[:struc_len], encoding=self.encoding)
                pcf_structs.append(resp_cfil)
                pcf_dict[resp_cfil["Parameter"]] = resp_cfil["IntegerList"]
            elif parm_type == pymqi.CMQCFC.MQCFT_STRING_LIST:
                resp_cfsl = CFSL()
                resp_cfsl.unpack(new_buff[:struc_len], encoding=self.encoding)
                if convert:
                    resp_cfsl["StringList"] = resp_cfsl["StringList"].decode(self.ccsid_str)
                    if len(resp_cfsl["StringList"]) != resp_cfsl["StringLength"] * resp_cfsl["Count"]:
                        print("Converted string length not equal to StringLength. Length: {} Expected Length: {} ".format(len(resp_cfsl["StringList"]), resp_cfsl["StringLength"] * resp_cfsl["Count"]))
                        raise pymqi.PYIFError("Converted string length not equal to StringLength. Length: {} Expected Length: {} ".format(len(resp_cfsl["StringList"]), resp_cfsl["StringLength"] * resp_cfsl["Count"]))
                   
                pcf_structs.append(resp_cfsl)
                pcf_dict[resp_cfsl["Parameter"]] = resp_cfsl["StringList"]    
            elif parm_type == pymqi.CMQCFC.MQCFT_BYTE_STRING:
                resp_cfbs = CFBS()
                resp_cfbs.unpack(new_buff[:struc_len], encoding=self.encoding) 
                pcf_structs.append(resp_cfbs)
                pcf_dict[resp_cfbs["Parameter"]] = resp_cfbs["String"]    
            else:
                print("Unsupported... (new_buff[:struc_len]:", binascii.hexlify(new_buff[:struc_len]))
                raise pymqi.PYIFError("Unsupported parameter type. Type: {}".format(parm_type))
                
            new_buff = new_buff[struc_len:]
            
            if len(new_buff) == 0:
                done = True
            
        return pcf_structs

    
    
    def execute_command(self, command, parm_list=[]):
        """execute_command(command, parm_list, convert)
        
        Execute a PCF command and optionally convert the codepage of the response messages."""
        #print "self.convert:", self.convert
        mqmd = pymqi.md()
        mqmd["Format"] = pymqi.CMQC.MQFMT_ADMIN
        mqmd["MsgType"] = pymqi.CMQC.MQMT_REQUEST
        #mqmd["ReplyToQ"] = "OUT3"
        
        mqmd["CodedCharSetId"] = self.ccsid
        
        mqmd["Encoding"] = self.encoding
        
        mqmd["Expiry"] = 300

        dynamic_queue_prefix = b"PCF.REPLY.*"
        dyn_od = pymqi.OD()
        dyn_od.ObjectName = b"SYSTEM.DEFAULT.MODEL.QUEUE"
        dyn_od.DynamicQName = dynamic_queue_prefix

        # Open the dynamic queue.
        dyn_input_open_options = pymqi.CMQC.MQOO_INPUT_SHARED + pymqi.CMQC.MQOO_INQUIRE + pymqi.CMQC.MQOO_FAIL_IF_QUIESCING
        dyn_queue = pymqi.Queue(self.qmgr, dyn_od, dyn_input_open_options)
        dyn_queue_name = dyn_od.ObjectName.strip()

        mqmd["ReplyToQ"] = dyn_queue_name
    
        put_opts = pymqi.pmo(Options = pymqi.CMQC.MQPMO_NO_SYNCPOINT + pymqi.CMQC.MQPMO_FAIL_IF_QUIESCING)

        msg_body = self.pack_bag(command, parm_list)

        #print("Msg Body:" + str(binascii.hexlify(msg_body)))
        self.qmgr.put1(self.command_queue, msg_body, mqmd, put_opts)
        
        get_opts = pymqi.gmo(Options = pymqi.CMQC.MQGMO_FAIL_IF_QUIESCING + pymqi.CMQC.MQGMO_NO_SYNCPOINT + pymqi.CMQC.MQGMO_WAIT)

        get_opts["Version"] = pymqi.CMQC.MQGMO_VERSION_2
        get_opts["MatchOptions"] = pymqi.CMQC.MQMO_MATCH_CORREL_ID
        get_opts["WaitInterval"] = 10 * 1000

        done = False
        out_structs = []

        while not done:
            try:
                get_mqmd = pymqi.md()
                get_mqmd["CorrelId"] = mqmd["MsgId"]
            
                message_data = dyn_queue.get(None, get_mqmd, get_opts)
                #print "Msg Data:", binascii.hexlify(message_data)
                #Hack check to determine if text can be converted safely. 
                if get_mqmd["CodedCharSetId"] != self.ccsid:
                    rep_structs = self.unpack_bag(message_data, convert=False)
                else:
                    rep_structs = self.unpack_bag(message_data, convert=self.convert)
                    
                if rep_structs[0]["Control"] == pymqi.CMQCFC.MQCFC_LAST:
                    done = True
                out_structs.append(rep_structs)
                
            except pymqi.MQMIError as e:
                if e.reason == 2033:
                    done = True
                else:
                    raise e
                
        pcf_r = PCFCommandResponse(out_structs)
        return pcf_r
    
    def inquire_qmgr(self, qmgr_attrs=None, stringify_keys=False):
        """inquire_qmgr(qmgr_attrs, stringify_keys)
        
        Helper method to inquire the attributes of a Queue Manager.  
        Use qmgr_attrs to specify the attributes to be returned.
        Use stringify_keys to stringify the PCF attributes that are returned."""
        
        parm_list = []
        if qmgr_attrs is not None:
            parm_list.append((pymqi.CMQCFC.MQIACF_Q_MGR_ATTRS, qmgr_attrs))
            
        pcf_r = self.execute_command(pymqi.CMQCFC.MQCMD_INQUIRE_Q_MGR, parm_list)
        if pcf_r.comp_code == pymqi.CMQC.MQCC_FAILED:
            return None
        else:
            if stringify_keys:
                return pcf_r.stringify_keys()[0]
            else:
                return pcf_r.parms[0]
    
    
    def inquire_q(self, queue_name="*", parms=None, q_attrs=None, stringify_keys=False):
        """inquire_q(queue_name, parms, q_attrs, stringify_keys)
        
        Helper method to inquire the attributes of a Queue.  
        Use parms and q_attrs to specify the attributes to be sent and returned.
        Use stringify_keys to stringify the PCF attributes that are returned."""
        
        if isinstance(queue_name, str):
            queue_name = queue_name.encode("ascii")
       
        parm_list = [{pymqi.CMQC.MQCA_Q_NAME: queue_name}]
        
        if parms is not None:
            for p in parms:
                parm_list.append(p)
        
        if q_attrs is not None:
            parm_list.append({pymqi.CMQCFC.MQIACF_Q_ATTRS: q_attrs})
                
        pcf_r = self.execute_command(pymqi.CMQCFC.MQCMD_INQUIRE_Q, parm_list)

        if pcf_r.comp_code == pymqi.CMQC.MQCC_FAILED:
            return None
        else:
            if stringify_keys:
                return pcf_r.stringify_keys()
            else:
                return pcf_r.parms
    
    
    def mqsc_command(self, mqsc_command, one_line=True):
        """mqsc_command(mqsc_command)
        
        Helper method to execute a MQSC command using PCF.
        Use one_line to return each MQSC Command response on one line."""
        
        if isinstance(mqsc_command, str):
            mqsc_command = mqsc_command.encode("ascii")

        ret = None
        if self.zos:
            ret = self.zos_mqsc_command(mqsc_command)
            return ret
        
        pcf_r =  self.execute_command(pymqi.CMQCFC.MQCMD_ESCAPE, [{pymqi.CMQCFC.MQIACF_ESCAPE_TYPE: pymqi.CMQCFC.MQET_MQSC}, {pymqi.CMQCFC.MQCACF_ESCAPE_TEXT: mqsc_command}])
        #print pcf_r.comp_code, pcf_r.reason_code
        if pcf_r.comp_code == pymqi.CMQC.MQCC_FAILED:
            print("MQSC command Failed!",pcf_r.comp_code, pcf_r.reason_code) 
            return None
        else:
            if len(pcf_r.parms) == 0:
                print("MQSC command Failed! No parms!")
                return None
            ret = b""
            #print pcf_r.stringify_keys()
            for p in pcf_r.parms:
                
                if pymqi.CMQCFC.MQCACF_ESCAPE_TEXT in p:
                    if one_line:
                        pos = p[pymqi.CMQCFC.MQCACF_ESCAPE_TEXT].find(b"\n")
                        ret = ret + p[pymqi.CMQCFC.MQCACF_ESCAPE_TEXT][0:pos+1] + p[pymqi.CMQCFC.MQCACF_ESCAPE_TEXT][pos:].strip().replace(b"\n", b" ") + b"\n"
                    else:
                        ret = ret + b"\n" + p[pymqi.CMQCFC.MQCACF_ESCAPE_TEXT]
            
            return ret

    def zos_mqsc_command(self, mqsc_command):
        """zos_mqsc_command(mqsc_command)
        
        Helper method to execute a MQSC command using the command queue as the "ESCAPE" PCF 
        command is not supported on Z/OS."""
        
        mqmd = pymqi.md()
        mqmd["Format"] = pymqi.CMQC.MQFMT_COMMAND_1
        mqmd["MsgType"] = pymqi.CMQC.MQMT_REQUEST
        
        mqmd["CodedCharSetId"] = self.ccsid
        
        mqmd["Encoding"] = self.encoding
        
        mqmd["Expiry"] = 300

        dynamic_queue_prefix = b"PCF.REPLY.*"
        dyn_od = pymqi.OD()
        dyn_od.ObjectName = b"SYSTEM.DEFAULT.MODEL.QUEUE"
        dyn_od.DynamicQName = dynamic_queue_prefix

        # Open the dynamic queue.
        dyn_input_open_options = pymqi.CMQC.MQOO_INPUT_SHARED + pymqi.CMQC.MQOO_INQUIRE + pymqi.CMQC.MQOO_FAIL_IF_QUIESCING
        dyn_queue = pymqi.Queue(self.qmgr, dyn_od, dyn_input_open_options)
        dyn_queue_name = dyn_od.ObjectName.strip()

        mqmd["ReplyToQ"] = dyn_queue_name
    
        put_opts = pymqi.pmo(Options = pymqi.CMQC.MQPMO_NO_SYNCPOINT + pymqi.CMQC.MQPMO_FAIL_IF_QUIESCING)
        if self.convert:
            msg_body = mqsc_command.encode(self.ccsid_str) 
        else:
            msg_body = mqsc_command
        
        self.qmgr.put1(self.command_queue, msg_body, mqmd, put_opts)
        
        get_opts = pymqi.gmo(Options = pymqi.CMQC.MQGMO_FAIL_IF_QUIESCING + pymqi.CMQC.MQGMO_NO_SYNCPOINT + pymqi.CMQC.MQGMO_WAIT)# + pymqi.CMQC.MQGMO_CONVERT)

        get_opts["Version"] = pymqi.CMQC.MQGMO_VERSION_2
        get_opts["MatchOptions"] = pymqi.CMQC.MQMO_MATCH_CORREL_ID
        get_opts["WaitInterval"] = 10 * 1000

        done = False
        resp_count = 0
        msg_count = 0
        out_resp = None
        while not done:
            try:
                
                get_mqmd = pymqi.md()
                get_mqmd["CorrelId"] = mqmd["MsgId"]
            
                message_data = dyn_queue.get(None, get_mqmd, get_opts)
                msg_count = msg_count + 1
                if out_resp is None:
                    out_resp = ""
                try:
                    if self.convert:
                        resp_msg_data = message_data.decode(self.ccsid_str)
                    else:
                        resp_msg_data = message_data
                        
                    remove_ws_re = "([\s]+)"
                    r = re.compile(remove_ws_re)
                    resp_msg_data = r.sub(" ", resp_msg_data)
                    out_resp = out_resp + resp_msg_data + "\n"
                    
                    if resp_msg_data.count("CSQN205I") > 0:
                        resp_count = int(resp_msg_data[resp_msg_data.find("COUNT=") + 6:resp_msg_data.find(",")])
                    
                    if resp_count != 0:
                        if msg_count >= resp_count:
                            done = True
                except Exception as e:
                    #print "%%%%%%%%%%%%%%%%%%%%", binascii.hexlify(message_data), "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
                    raise e

                #rep_structs = self.unpack_bag(message_data, encoding=self.encoding)
                #if rep_structs[0]["Control"] == pymqi.CMQCFC.MQCFC_LAST:
                #    done = True
                #out_structs.append(rep_structs)
                
            except pymqi.MQMIError as e:
                if e.reason == 2033:
                    done = True
                else:
                    raise e

        return out_resp
    

      
if __name__ == '__main__':
    
    epilog = """
    """

    parser = argparse.ArgumentParser(description="MQSC command script/MQPCF Tests", epilog=epilog, formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument("-H", "--host", action="store", type=str, dest="host", help="The MQ server host name.", default=None)
    #parser.add_argument("-P", "--port", action="store", type=str, dest="port", help="The MQ lisstener port.", default=1414)
    parser.add_argument("-q", "--queue_manager", action="store", type=str, dest="queue_manager", help="The MQ Queue Manager name.", default=None)
    parser.add_argument("-c", "--channel", action="store", type=str, dest="channel", help="The MQ server connection channel.", default=None)
    parser.add_argument("-u", "--user", action="store", type=str, dest="user", help="The user name (if MQ requires user authentication).", default=None)
    parser.add_argument("-p", "--password", action="store", type=str, dest="password", help="The password (if MQ requires user authentication).", default=None)

    parser.add_argument("-m", "--mqsc", action="store", type=str, dest="mqsc", help="The mqsc comand to process.  If not present standard input will be read.", default=None)

    parser.add_argument("-l", "--output_on_one_line", action="store_true",  dest="output_on_one_line", help="Output the MQSC command responses on one line per response.", default=True)
    
    parser.add_argument("-z", "--zos", action="store_true", dest="zos", help="Remote queue manager is a Z/OS queue manager(CP037 is implied)", default=False)

    parser.add_argument("-v", "--verbose", action="store_true", dest="verbose", help="Verbose. ", default=False)
    parser.add_argument("-t", "--run-tests", action="store_true", dest="run_tests", help="Run tests instead of a MQSC command. ", default=False)

    args = parser.parse_args()

    if args.host is None:
        print("Host required.")
        parser.print_help()
        sys.exit(8)

    if args.channel is None:
        print("Channel required.")
        parser.print_help()
        sys.exit(8)

    if args.queue_manager is None:
        print("QM Name required.")
        parser.print_help()
        sys.exit(8)

    # USER_NAME = "hannes"
    # PASSWORD = "rocks"
        
    qm = args.queue_manager
    chl = args.channel

    ls = args.host
    #print ls
    user_name = args.user
    password = args.password
    ccsid = 0
    encoding = 0
    convert = False
    mqsc = ""
    
    if args.mqsc:
        mqsc = str(args.mqsc)
    else:
        if not args.run_tests:
            mqsc = str(sys.stdin.read())
    
    #print "mqsc_len:", len(mqsc)
    #print "mqsc: <{}>".format(mqsc)
    if args.zos:
        ccsid = 37
        encoding = 785
        convert = True
    
   
#         
#     qm = "LDB0"
#     chl = "LDB0.CLIENT"
#     ls = "127.0.0.1(1414)"
# #     
    
    try:    
        qmgr = pymqi.QueueManager(None)
        #print "Connecting..."
        qmgr.connectTCPClient(qm, pymqi.cd(), chl, ls, user_name, password)
        #print "Connected..."
        #pcf_c = PCFCommand(qmgr, ccsid=037)
        pcf_c = PCFCommand(qmgr, ccsid=ccsid, encoding=encoding, convert=convert, zos=args.zos)
        #print "\nInquire Queue Manager using execute_command..."
        #print mqsc
        if not args.run_tests:

            result = ""
            for cmd in mqsc.split("\n"):
                cmd = cmd.replace("\n", "").strip()
                if cmd != "":
                    res = pcf_c.mqsc_command(cmd.replace("\n", ""), one_line=args.output_on_one_line)
                    result = result + str(res)
                
            print(result)
        else:
           
            print("\n--------------- Inquire queue manager all --------------------")
            pcf_r = pcf_c.execute_command(pymqi.CMQCFC.MQCMD_INQUIRE_Q_MGR,[(pymqi.CMQCFC.MQIACF_Q_MGR_ATTRS, [pymqi.CMQC.MQCA_ALTERATION_DATE])])
            print("Comp code:", pcf_r.comp_code, " Reason code:", pcf_r.reason_code)
            print(pcf_r.stringify_keys())
            
            print("\n--------------- QM attrs all with exec:----------------")
            pcf_r = pcf_c.execute_command(pymqi.CMQCFC.MQCMD_INQUIRE_Q_MGR)
            print(pcf_r)
            
            print("\n--------------- QM attrs all with inquire_qm:--------------------------")
            qm_resp = pcf_c.inquire_qmgr(stringify_keys=False)
            print("Alteration date is:" + str(qm_resp[pymqi.CMQC.MQCA_ALTERATION_DATE])) 
            
            print("\n--------------- QM Only MQCA_ALTERATION_DATE with exec:-------------------")
            pcf_r = pcf_c.execute_command(pymqi.CMQCFC.MQCMD_INQUIRE_Q_MGR, [(pymqi.CMQCFC.MQIACF_Q_MGR_ATTRS, [pymqi.CMQC.MQCA_ALTERATION_DATE])])
            print(pcf_r)
            print("Comp code:", pcf_r.comp_code, " Reason code:", pcf_r.reason_code)
            print("Alteration date is:" + str(pcf_r.parms[0][pymqi.CMQC.MQCA_ALTERATION_DATE]))
            #print("Alteration date is getattr:" + str(pcf_r[pymqi.CMQC.MQCA_ALTERATION_DATE]))
            
            print("\n--------------- QM Only MQCA_ALTERATION_DATE - stringified:--------------")
            print(pcf_c.inquire_qmgr(qmgr_attrs=[pymqi.CMQC.MQCA_ALTERATION_DATE], stringify_keys=True))
            print("\n--------------- QM MQCA_ALTERATION_DATE - not stringified:----------")
            print(pcf_c.inquire_qmgr(qmgr_attrs=[pymqi.CMQC.MQCA_ALTERATION_DATE], stringify_keys=False))


            print("\n--------------- Inquire_q. by Q type ------------------")
            q_resp = pcf_c.inquire_q("SYSTEM.DEFAULT.*", parms=[{pymqi.CMQC.MQIA_Q_TYPE: pymqi.CMQC.MQQT_LOCAL}], stringify_keys=False)
            print(q_resp)
            print("\n-------------------------")
            for q in q_resp:
                print("Q Name:", q[pymqi.CMQC.MQCA_Q_NAME], "Q depth:", q[pymqi.CMQC.MQIA_CURRENT_Q_DEPTH])


            print("\n--------------- Inquire_q. by Q type - not stringified--------------")
            print(pcf_c.inquire_q("SYSTEM.DEFAULT.*", parms=[{pymqi.CMQC.MQIA_Q_TYPE: pymqi.CMQC.MQQT_LOCAL}], stringify_keys=False))

            print("\n--------------- Inquire_q.  Q type with attrs-----------------------")
            print(pcf_c.inquire_q("SYSTEM.DEFAULT.*", parms=[{pymqi.CMQC.MQIA_Q_TYPE: pymqi.CMQC.MQQT_LOCAL}], q_attrs=[pymqi.CMQC.MQCA_Q_NAME, pymqi.CMQC.MQIA_CURRENT_Q_DEPTH], stringify_keys=True))

            print("\n--------------- Inquire_q.  Q type - tuple parms with attrs-----------------------------------------------")
            print(pcf_c.inquire_q("SYSTEM.DEFAULT.*", parms=[(pymqi.CMQC.MQIA_Q_TYPE, pymqi.CMQC.MQQT_LOCAL)], q_attrs=[pymqi.CMQC.MQCA_Q_NAME, pymqi.CMQC.MQIA_CURRENT_Q_DEPTH], stringify_keys=False))
            
  
            print("\n--------------- DIS QL(SYSTEM.DEFAULT.*) using mqsc_command...-----------")
            print(pcf_c.mqsc_command("DIS QL(SYSTEM.DEFAULT.*) ALL"))
            #print pcf_c.mqsc_command("DIS Q(SYSTEM.*) ")
            
            print("\n--------------- DIS QL(SYSTEM.DEFAULT.*) using ESCAPE...-----------------")
            if args.zos:
                print(pcf_c.execute_command(pymqi.CMQCFC.MQCMD_ESCAPE, [(pymqi.CMQCFC.MQIACF_ESCAPE_TYPE, pymqi.CMQCFC.MQET_MQSC), (pymqi.CMQCFC.MQCACF_ESCAPE_TEXT, "DIS QL(SYSTEM.DEFAULT.*)".encode("cp037"))]))
            else:
                print(pcf_c.execute_command(pymqi.CMQCFC.MQCMD_ESCAPE, [(pymqi.CMQCFC.MQIACF_ESCAPE_TYPE, pymqi.CMQCFC.MQET_MQSC), (pymqi.CMQCFC.MQCACF_ESCAPE_TEXT, b"DIS QL(SYSTEM.DEFAULT.*)")]))

     
            print("\n--------------- Inquire_q. with exec:-------------------")
            pcf_r = pcf_c.execute_command(pymqi.CMQCFC.MQCMD_INQUIRE_Q, [(pymqi.CMQC.MQCA_Q_NAME, b"SYSTEM.DEFAULT.*"), (pymqi.CMQC.MQIA_Q_TYPE, pymqi.CMQC.MQQT_LOCAL), (pymqi.CMQCFC.MQIACF_Q_ATTRS, [pymqi.CMQC.MQCA_Q_NAME,pymqi.CMQC.MQIA_Q_TYPE,pymqi.CMQC.MQIA_MAX_Q_DEPTH])])
            print(pcf_r)
            print("Comp code:", pcf_r.comp_code, " Reason code:", pcf_r.reason_code)
            for q in pcf_r.parms:
                print(q)



            print("\n--------------- create PYMQI.PCF.TEST.QUEUE queue -----------------")
            create_q_parms= [(pymqi.CMQC.MQCA_Q_NAME, b"PYMQI.PCF.TEST.QUEUE"), (pymqi.CMQC.MQIA_Q_TYPE, pymqi.CMQC.MQQT_LOCAL), (pymqi.CMQC.MQIA_MAX_Q_DEPTH, 10), ]
            pcf_r = pcf_c.execute_command(pymqi.CMQCFC.MQCMD_CREATE_Q, create_q_parms)
            print("Comp code:", pcf_r.comp_code, " Reason code:", pcf_r.reason_code)
            print(pcf_r)
            
            print("\n--------------- Inquire_q PYMQI.PCF.TEST.QUEUE.  Q type - tuple parms with attrs-----------------------------------------------")
            print(pcf_c.inquire_q("PYMQI.PCF.TEST.QUEUE", parms=[(pymqi.CMQC.MQIA_Q_TYPE, pymqi.CMQC.MQQT_LOCAL)], q_attrs=[pymqi.CMQC.MQCA_Q_NAME, pymqi.CMQC.MQIA_CURRENT_Q_DEPTH], stringify_keys=False))
            
            print("\n--------------- Delete PYMQI.PCF.TEST.QUEUE qeueue -----------------")
            del_q_parms= [(pymqi.CMQC.MQCA_Q_NAME, b"PYMQI.PCF.TEST.QUEUE"), (pymqi.CMQC.MQIA_Q_TYPE, pymqi.CMQC.MQQT_LOCAL)]
            pcf_r = pcf_c.execute_command(pymqi.CMQCFC.MQCMD_DELETE_Q, del_q_parms)
            print("Comp code:", pcf_r.comp_code, " Reason code:", pcf_r.reason_code)
            print(pcf_r)

            if args.zos:
                print("MQSC - MQCMD_ESCAPE - using execute command.  show zos not supported.-----------------------------------------  ")
                print(pcf_c.execute_command(pymqi.CMQCFC.MQCMD_ESCAPE, [(pymqi.CMQCFC.MQIACF_ESCAPE_TYPE, pymqi.CMQCFC.MQET_MQSC), (pymqi.CMQCFC.MQCACF_ESCAPE_TEXT, "DIS QL(*)".encode("cp037"))]))
                # print "CMD MQCMD_ESCAPE with convert."
                # print pcf_c.execute_command_d(pymqi.CMQCFC.MQCMD_ESCAPE, [{pymqi.CMQCFC.MQIACF_ESCAPE_TYPE: pymqi.CMQCFC.MQET_MQSC}, {pymqi.CMQCFC.MQCACF_ESCAPE_TEXT: "DIS QL(*)".encode("cp037")}], convert=True)


    except Exception as ex:
        print(str(ex))
    
