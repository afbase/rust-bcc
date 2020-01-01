use bcc::core::BPF;
use std::sys_common::net::hntohs;
use std::collections::HashMap;
use clap::{App, Arg};
use failure::Error;

use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{fmt, mem, ptr, thread, time};

// lazy borrowing from tcpconnect.py
const struct_init: HashMap<&str, HashMap<&str, &str>> = [
("ipv4",
    [("count",
        "struct ipv4_flow_key_t flow_key = {};
        flow_key.saddr = skp->__sk_common.skc_rcv_saddr;
        flow_key.daddr = skp->__sk_common.skc_daddr;
        flow_key.dport = ntohs(dport);
        ipv4_count.increment(flow_key);"),
    ("trace",
        "struct ipv4_data_t data4 = {.pid = pid, .ip = ipver};
        data4.uid = bpf_get_current_uid_gid();
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        data4.saddr = skp->__sk_common.skc_rcv_saddr;
        data4.daddr = skp->__sk_common.skc_daddr;
        data4.dport = ntohs(dport);
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));")].iter().cloned().collect(),
"ipv6",
    [("count",
        "struct ipv6_flow_key_t flow_key = {};
        bpf_probe_read(&flow_key.saddr, sizeof(flow_key.saddr),
           skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&flow_key.daddr, sizeof(flow_key.daddr),
           skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        flow_key.dport = ntohs(dport);
        ipv6_count.increment(flow_key);"),
    ("trace",
        "struct ipv6_data_t data6 = {.pid = pid, .ip = ipver};
        data6.uid = bpf_get_current_uid_gid();
        data6.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
           skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
           skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.dport = ntohs(dport);
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));")].iter().cloned().collect()].iter().cloned().collect();

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), Error> {
    let mut bpf_text = include_str!("tcpconnect.c");
    let matches = App::new("tcpconnect")
        .about("Trace TCP connects")
        .longabout("examples:
./tcpconnect           # trace all TCP connect()s
./tcpconnect -t        # include timestamps
./tcpconnect -p 181    # only trace PID 181
./tcpconnect -P 80     # only trace port 80
./tcpconnect -P 80,81  # only trace port 80 and 81
./tcpconnect -U        # include UID
./tcpconnect -u 1000   # only trace UID 1000
./tcpconnect -c        # count connects per src ip and dest ip/port")
        .arg(
            Arg::with_name("t")
            .longname("timestamp")
            .takes_value(false)
            .help("include timestamp on output")
        )
        .arg(
            Arg::with_name("p")
            .help("trace this PID only")
            .value_name("PID")
            .number_of_values(1)
            .takes_value(true)
        )
        .arg(
            Arg::with_name("P")
            .help("comma-separated list of destination ports to trace.")
            .value_name("PORT")
            .min_values(1)
            .takes_value(true)
        )
        .arg(
            Arg::with_name("U")
            .longname("print-uid")
            .help("include UID on output")
            .value_name("print-uid")
            .takes_value(false)
        )
        .arg(
            Arg::with_name("u")
            .longname("uid")
            .help("trace this UID only")
            .value_name("UID")
            .number_of_values(1)
            .takes_value(true)
        )
        .arg(
            Arg::with_name("c")
            .longname("count")
            .help("count connects per src ip and dest ip/port")
            .value_name("count")
            .takes_value(true)
        )
        .arg(
            Arg::with_name("ebpf")
            .takes_value(false)
        );
        let timestamp = matches.is_present("t");
        let print_uuid = matches.is_present("U");
        let ebpf = matches.is_present("ebpf");
        let count = matches.is_present("c");
        if let Some(p) = matches.value_of("p") {
            // trace pid
            let pid = p.parse::<u32>();
            bpf_text.replace("FILTER_PID",
            format!("if (pid != %s) { return 0; }", pid);
        }
        if let Some(P) = matches.value_of("P") {
            // trace ports
            let ports_conditions: Vec<str> = P.collect().map(|v| format!("dport != %d", ntohs(v.parse::<u16>())));
            let port_contition_statement = ports_conditions.join(" && ");
            bpf_text.replace("FILTER_PORT", format!("if (%s) { currsock.delete(&pid); return 0; }",port_contition_statement));
        }
        if let Some(u) = matches.value_of("u") {
            // trace uuid
            let uuid = u.parse::<u32>();
            bpf_text.replace("FILTER_UID", format!("if (uid != %s) { return 0; }",uuid);
        }
        bpf_text.replace("FILTER_PID", "");
        bpf_text.replace("FILTER_PORT", "");
        bpf_text.replace("FILTER_UID", "");

        // compile the above BPF code!
        let mut module = BPF::new(bpf_text)?;
        // load + attach tracepoints!
        let trace_connect_entry = module.load_kprobe("trace_connect_entry")
        let trace_connect_entry = module.load_kprobe("trace_connect_entry")
        let trace_connect_v4_return = module.load_kprobe("trace_connect_v4_return")
        let trace_connect_v6_return = module.load_kprobe("trace_connect_v6_return")
}

fn print_ipv4_event(cpu: &str, data: &str, size: &str){

}

fn print_ipv6_event(cpu: &str, data: &str, size: &str){
    
}

fn depict_cnt(counts_tab: u32, l3prot: &str){

}

fn main() {
    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set handler for SIGINT / SIGTERM");

    match do_main(runnable) {
        Err(x) => {
            eprintln!("Error: {}", x);
            eprintln!("{}", x.backtrace());
            std::process::exit(1);
        }
        _ => {}
    }
}