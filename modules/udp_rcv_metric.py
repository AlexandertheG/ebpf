from bcc import BPF
import ctypes as ct
from collections import Counter
import json
from threading import Thread

class Data(ct.Structure):
    _fields_ = [
        ('ifindex', ct.c_uint32)
    ]

class UdpRcvMetric:

    def __init__(self):

        self.aggregates = Counter()

        bpf_source = """
        #include <uapi/linux/ptrace.h>
        BPF_PERF_OUTPUT(events);

        struct data_t {
            u32 ifindex;  // inteface index
        };

        int do_udp_rcv(struct pt_regs *ctx, struct __sk_buff *skb) {
        struct data_t data = {};

        if(skb->pkt_type == 0) {
            data.ifindex = skb->ifindex;
            events.perf_submit(ctx, &data, sizeof(data));
        }
        return 0;
        }
        """

        self.bpf = BPF(text = bpf_source)
        self.bpf.attach_kprobe(event='udp_rcv', fn_name="do_udp_rcv")
        self.bpf["events"].open_perf_buffer(self.__count_udp_rcvs)

        t = Thread(target=self.__poll_perf_buffer)
        t.start()

    def __poll_perf_buffer(self):
            while True:
                    self.bpf.perf_buffer_poll()

    def __count_udp_rcvs(self, cpu, data, size):
            data = ct.cast(data, ct.POINTER(Data)).contents
            self.aggregates[data.ifindex] += 1

    def __get_prometheus_format(self):
        arr = []
        for k, v in self.aggregates.items():
            res = "udp_rcv{" + "ifindex=\"{}\"".format(k) + "} " + "{}".format(v)
            arr.append(res)
        return "\n".join(arr)

    def get_metric(self) -> str:
        return self.__get_prometheus_format()