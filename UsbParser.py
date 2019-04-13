"ported from lsusb.py by lvxiaoliang"

import os, sys, re

# from __future__ import print_function

# Global options
warnsort = False

prefix = "/sys/bus/usb/devices/"
usbids = "usb.ids"

def readattr(path, name):
    "Read attribute from sysfs and return as string"
    f = open(prefix + path + "/" + name);
    return f.readline().rstrip("\n");

def readlink(path, name):
    "Read symlink and return basename"
    return os.path.basename(os.readlink(prefix + path + "/" + name));

class UsbClass:
    "Container for USB Class/Subclass/Protocol"
    def __init__(self, cl, sc, pr, str = ""):
        self.pclass = cl
        self.subclass = sc
        self.proto = pr
        self.desc = str
    def __repr__(self):
        return self.desc
    def __cmp__(self, oth):
        # Works only on 64bit systems:
        #return self.pclass*0x10000+self.subclass*0x100+self.proto \
        #    - oth.pclass*0x10000-oth.subclass*0x100-oth.proto
        if self.pclass != oth.pclass:
            return self.pclass - oth.pclass
        if self.subclass != oth.subclass:
            return self.subclass - oth.subclass
        return self.proto - oth.proto

class UsbVendor:
    "Container for USB Vendors"
    def __init__(self, vid, vname = ""):
        self.vid = vid
        self.vname = vname
    def __repr__(self):
        return self.vname
    def __cmp__(self, oth):
        return self.vid - oth.vid

class UsbProduct:
    "Container for USB VID:PID devices"
    def __init__(self, vid, pid, pname = ""):
        self.vid = vid
        self.pid = pid
        self.pname = pname
    def __repr__(self):
        return self.pname
    def __cmp__(self, oth):
        # Works only on 64bit systems:
        # return self.vid*0x10000 + self.pid \
        #    - oth.vid*0x10000 - oth.pid
        if self.vid != oth.vid:
            return self.vid - oth.vid
        return self.pid - oth.pid

usbvendors = []
usbproducts = []
usbclasses = []

def ishexdigit(str):
    "return True if all digits are valid hex digits"
    for dg in str:
        if not dg.isdigit() and not dg in 'abcdef':
            return False
    return True

def parse_usb_ids():
    "Parse /usr/share/usb.ids and fill usbvendors, usbproducts, usbclasses"
    id = 0
    sid = 0
    mode = 0
    strg = ""
    cstrg = ""
    for ln in file(usbids, "r").readlines():
        if ln[0] == '#':
            continue
        ln = ln.rstrip('\n')
        if len(ln) == 0:
            continue
        if ishexdigit(ln[0:4]):
            mode = 0
            id = int(ln[:4], 16)
            usbvendors.append(UsbVendor(id, ln[6:]))
            continue
        if ln[0] == '\t' and ishexdigit(ln[1:3]):
            sid = int(ln[1:5], 16)
            # USB devices
            if mode == 0:
                usbproducts.append(UsbProduct(id, sid, ln[7:]))
                continue
            elif mode == 1:
                nm = ln[5:]
                if nm != "Unused":
                    strg = cstrg + ":" + nm
                else:
                    strg = cstrg + ":"
                usbclasses.append(UsbClass(id, sid, -1, strg))
                continue
        if ln[0] == 'C':
            mode = 1
            id = int(ln[2:4], 16)
            cstrg = ln[6:]
            usbclasses.append(UsbClass(id, -1, -1, cstrg))
            continue
        if mode == 1 and ln[0] == '\t' and ln[1] == '\t' and ishexdigit(ln[2:4]):
            prid = int(ln[2:4], 16)
            usbclasses.append(UsbClass(id, sid, prid, strg + ":" + ln[6:]))
            continue
        mode = 2

def bin_search(first, last, item, list):
    "binary search on list, returns -1 on fail, match idx otherwise, recursive"
    #print "bin_search(%i,%i)" % (first, last)
    if first == last:
        return -1
    if first == last-1:
        if item == list[first]:
            return first
        else:
            return -1
    mid = (first+last) // 2
    if item == list[mid]:
        return mid
    elif item < list[mid]:
        return bin_search(first, mid, item, list)
    else:
        return bin_search(mid, last, item, list)


def find_usb_prod(vid, pid):
    "Return device name from USB Vendor:Product list"
    strg = ""
    dev = UsbVendor(vid, "")
    lnvend = len(usbvendors)
    ix = bin_search(0, lnvend, dev, usbvendors)
    if ix != -1:
        strg = usbvendors[ix].__repr__()
    else:
        return ""
    dev = UsbProduct(vid, pid, "")
    lnprod = len(usbproducts)
    ix = bin_search(0, lnprod, dev, usbproducts)
    if ix != -1:
        return strg + " " + usbproducts[ix].__repr__()
    return strg

def find_usb_class(cid, sid, pid):
    "Return USB protocol from usbclasses list"
    if cid == 0xff and sid == 0xff and pid == 0xff:
        return "Vendor Specific"
    lnlst = len(usbclasses)
    dev = UsbClass(cid, sid, pid, "")
    ix = bin_search(0, lnlst, dev, usbclasses)
    if ix != -1:
        return usbclasses[ix].__repr__()
    dev = UsbClass(cid, sid, -1, "")
    ix = bin_search(0, lnlst, dev, usbclasses)
    if ix != -1:
        return usbclasses[ix].__repr__()
    dev = UsbClass(cid, -1, -1, "")
    ix = bin_search(0, lnlst, dev, usbclasses)
    if ix != -1:
        return usbclasses[ix].__repr__()
    return ""


devlst = (    'usb/lp',    # usblp
        'host',     # usb-storage
        'video4linux/video',     # uvcvideo et al.
        'sound/card',    # snd-usb-audio
        'net/',     # cdc_ether, ...
        'input/input',    # usbhid
        'bluetooth/hci',    # btusb
        'ttyUSB',    # btusb
        'tty/',        # cdc_acm
    )

def find_storage(hostno):
    "Return SCSI block dev names for host"
    res = ""
    for ent in os.listdir("/sys/class/scsi_device/"):
        (host, bus, tgt, lun) = ent.split(":")
        if host == hostno:
            try:
                for ent2 in os.listdir("/sys/class/scsi_device/%s/device/block" % ent):
                    res += ent2 + " "
            except:
                pass
    return res

def find_dev(driver, usbname):
    "Return pseudo devname that's driven by driver"
    res = ""
    for nm in devlst:
        dir = prefix + usbname
        prep = ""
        #print nm
        idx = nm.find('/')
        if idx != -1:
            prep = nm[:idx+1]
            dir += "/" + nm[:idx]
            nm = nm[idx+1:]
        ln = len(nm)
        try:
            for ent in os.listdir(dir):
                if ent[:ln] == nm:
                    res += prep+ent+" "
                    if nm == "host":
                        res += "(" + find_storage(ent[ln:])[:-1] + ")"
        except:
            pass
    return res


class UsbInterface:
    "Container for USB interface info"
    def __init__(self, parent = None, level = 1):
        self.parent = parent
        self.level = level
        self.fname = ""
        self.iclass = 0
        self.isclass = 0
        self.iproto = 0
        self.noep = 0
        self.driver = ""
        self.devname = ""
        self.protoname = ""
    def read(self, fname):
        fullpath = ""
        if self.parent:
            fullpath += self.parent.fname + "/"
        fullpath += fname
        #self.fname = fullpath
        self.fname = fname
        self.iclass = int(readattr(fullpath, "bInterfaceClass"),16)
        self.isclass = int(readattr(fullpath, "bInterfaceSubClass"),16)
        self.iproto = int(readattr(fullpath, "bInterfaceProtocol"),16)
        self.noep = int(readattr(fullpath, "bNumEndpoints"))
        try:
            self.driver = readlink(fname, "driver")
            self.devname = find_dev(self.driver, fname)
        except:
            pass
        self.protoname = find_usb_class(self.iclass, self.isclass, self.iproto)

class UsbDevice:
    "Container for USB device info"
    def __init__(self, parent = None, level = 0):
        self.parent = parent
        self.level = level
        self.fname = ""
        self.iclass = 0
        self.isclass = 0
        self.iproto = 0
        self.vid = 0
        self.pid = 0
        self.name = ""
        self.usbver = ""
        self.speed = ""
        self.maxpower = ""
        self.noports = 0
        self.nointerfaces = 0
        self.driver = ""
        self.devname = ""
        self.productname = ""
        self.manufacturername = ""
        self.interfaces = []
        self.children = []

    def read(self, fname):
        self.fname = fname
        self.iclass = int(readattr(fname, "bDeviceClass"), 16)
        self.isclass = int(readattr(fname, "bDeviceSubClass"), 16)
        self.iproto = int(readattr(fname, "bDeviceProtocol"), 16)
        self.vid = int(readattr(fname, "idVendor"), 16)
        self.pid = int(readattr(fname, "idProduct"), 16)
        try:
            self.productname = readattr(fname, "product")
            self.manufacturername = readattr(fname, "manufacturer")
            self.name = readattr(fname, "manufacturer") + " " \
                  + readattr(fname, "product")
            self.name += " " + readattr(fname, "serial")
            if self.name[:5] == "Linux":
                rx = re.compile(r"Linux [^ ]* (.hci_hcd) .HCI Host Controller ([0-9a-f:\.]*)")
                mch = rx.match(self.name)
                if mch:
                    self.name = mch.group(1) + " " + mch.group(2)

        except:
            pass
        if not self.name:
            self.name = find_usb_prod(self.vid, self.pid)
        self.usbver = readattr(fname, "version")
        self.speed = readattr(fname, "speed")
        self.maxpower = readattr(fname, "bMaxPower")
        self.noports = int(readattr(fname, "maxchild"))
        self.nointerfaces = int(readattr(fname, "bNumInterfaces"))
        try:
            self.driver = readlink(fname, "driver")
            self.devname = find_dev(self.driver, fname)
        except:
            pass

    def readchildren(self):
        if self.fname[0:3] == "usb":
            fname = self.fname[3:]
        else:
            fname = self.fname
        for dirent in os.listdir(prefix + self.fname):
            if not dirent[0:1].isdigit():
                continue
            #print dirent
            if os.access(prefix + dirent + "/bInterfaceClass", os.R_OK):
                iface = UsbInterface(self, self.level+1)
                iface.read(dirent)
                self.interfaces.append(iface)
            else:
                usbdev = UsbDevice(self, self.level+1)
                usbdev.read(dirent)
                usbdev.readchildren()
                self.children.append(usbdev)

def deepcopy(lst):
    "Returns a deep copy from the list lst"
    copy = []
    for item in lst:
        copy.append(item)
    return copy

def display_diff(lst1, lst2, fmtstr, args):
    "Compare lists (same length!) and display differences"
    for idx in range(0, len(lst1)):
        if lst1[idx] != lst2[idx]:
            print "Warning: " + fmtstr % args(lst2[idx])

def fix_usbvend():
    "Sort USB vendor list and (optionally) display diffs"
    if warnsort:
        oldusbvend = deepcopy(usbvendors)
    usbvendors.sort()
    if warnsort:
        display_diff(usbvendors, oldusbvend,
                "Unsorted Vendor ID %04x",
                lambda x: (x.vid,))

def fix_usbprod():
    "Sort USB products list"
    if warnsort:
        oldusbprod = deepcopy(usbproducts)
    usbproducts.sort()
    if warnsort:
        display_diff(usbproducts, oldusbprod,
                "Unsorted Vendor:Product ID %04x:%04x",
                lambda x: (x.vid, x.pid))

def fix_usbclass():
    "Sort USB class list"
    if warnsort:
        oldusbcls = deepcopy(usbclasses)
    usbclasses.sort()
    if warnsort:
        display_diff(usbclasses, oldusbcls,
                "Unsorted USB class %02x:%02x:%02x",
                lambda x: (x.pclass, x.subclass, x.proto))

def scan_children(usbdev, usbdevLists):
    usbdevLists.append(usbdev)
    for child in usbdev.children:
        scan_children(child, usbdevLists)
    return

def read_usb():
    "Read toplevel USB entries and print"
    usbdevLists = []
    for dirent in os.listdir(prefix):
        #print dirent,
        if not dirent[0:3] == "usb":
            continue
        usbdev = UsbDevice(None, 0)
        usbdev.read(dirent)
        usbdev.readchildren()
        scan_children(usbdev, usbdevLists)

    return usbdevLists

parse_usb_ids()
fix_usbvend()
fix_usbprod()
fix_usbclass()

def get_usb_devs():
    return read_usb()

# Entry point
if __name__ == "__main__":
    get_usb_devs()

