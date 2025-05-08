#!/usr/bin/env python3
#   PScap                  v1.4
#   License            MIT 2025
#   Author         jts.gg/pscap

import os
import sys
import logging
import psutil
from scapy.all import sniff
from scapy.utils import PcapWriter

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s", level=logging.INFO
)

def usage():
    print("""
  PScap v1.4    Capture network traffic per PID/ProcessName
  Author        jts.gg/pscap

  python3 pscap.py [options]

Options:
  -l                List running processes and exit
  -p <targets>      Comma-separated PIDs or process names (example.exe)
  -i <iface>        Interface to sniff on (default: all)
  -o <outfile>      Output PCAP file (default: pid_<PIDs>.pcap)
  -b <blacklist>    Comma-separated ports to exclude
  -h, --help        Show this help and exit
""")
    sys.exit(1)


def is_admin():
    try:
        if os.name == 'nt':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except:
        return False


def list_processes():
    for p in psutil.process_iter(['pid','name']):
        nm = p.info['name'] or ''
        print(f"{p.info['pid']:>6}  {nm}")


def parse_targets(s):
    pids, names = set(), []
    for tok in s.split(','):
        tok = tok.strip()
        if not tok:
            continue
        if tok.isdigit():
            pids.add(int(tok))
        else:
            names.append(tok.lower())
    if names:
        # map names → PIDs
        for p in psutil.process_iter(['pid','name']):
            nm = (p.info['name'] or '').lower()
            if nm in names:
                pids.add(p.info['pid'])
        # report missing
        for nm in names:
            if not any((p.info['name'] or '').lower()==nm
                       for p in psutil.process_iter(['name'])):
                logging.error(f"No process named '{nm}' found.")
    return sorted(pids)


def get_ports(pids):
    ports = set()
    for pid in pids:
        try:
            proc = psutil.Process(pid)
            for c in proc.net_connections(kind='inet'):
                if c.laddr and c.laddr.port:
                    ports.add(c.laddr.port)
                if c.raddr and c.raddr.port:
                    ports.add(c.raddr.port)
        except psutil.NoSuchProcess:
            logging.warning(f"PID {pid} disappeared; skipping.")
    return ports


def build_bpf(ports, blacklist):
    if not ports:
        return None
    terms = []
    for p in ports:
        terms += [f"tcp port {p}", f"udp port {p}"]
    bpf = " or ".join(terms)
    blk = [b for b in blacklist if isinstance(b,int)]
    if blk:
        excl = " or ".join(f"port {b}" for b in blk)
        bpf = f"({bpf}) and not ({excl})"
    return bpf


def main():
    do_list  = False
    targets  = None
    iface    = None
    outfile  = None
    blacklist = ""

    args = sys.argv[1:]
    if not args:
        usage()

    while args:
        opt = args.pop(0)
        if opt in ('-h','--help'):
            usage()
        elif opt == '-l':
            do_list = True
        elif opt == '-p':
            if not args: usage()
            targets = args.pop(0)
        elif opt == '-i':
            if not args: usage()
            iface = args.pop(0)
        elif opt == '-o':
            if not args: usage()
            outfile = args.pop(0)
        elif opt == '-b':
            if not args: usage()
            blacklist = args.pop(0)
        else:
            print(f"Unknown option: {opt}")
            usage()

    if do_list:
        list_processes()
        return

    if not targets:
        print("Error: must specify -l or -p <targets>")
        usage()

    if not is_admin():
        sys.exit("Error: Administrator/root privileges required.")

    pids = parse_targets(targets)
    if not pids:
        sys.exit("Error: No valid PIDs found.")

    blk = {int(x) for x in blacklist.split(',') if x.strip().isdigit()}
    ports = get_ports(pids)
    if not ports:
        sys.exit("Error: No open sockets for target PID(s).")

    bpf = build_bpf(ports, blk)
    out = outfile or f"pid_{'_'.join(map(str,pids))}.pcap"
    writer = PcapWriter(out, append=False, sync=True)

    logging.info(f"Capturing PIDs {pids} on iface={iface or 'all'}")
    logging.info(f"Ports={sorted(ports)} skip={sorted(blk)} → {out}")
    logging.info(f"BPF filter: {bpf or 'none'}")

    try:
        sniff(iface=iface, filter=bpf, prn=writer.write, store=False)
    except KeyboardInterrupt:
        logging.info("Capture interrupted by user")
    finally:
        writer.close()
        logging.info(f"Capture saved: {out}")

if __name__=='__main__':
    main()
