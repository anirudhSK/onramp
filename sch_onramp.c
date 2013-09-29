#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>

static int onramp_enqueue(struct sk_buff *skb, struct Qdisc *sch) { printk("Enqueueing\n"); return 0; }

static struct sk_buff *onramp_dequeue(struct Qdisc *sch) { printk("Dequeueing\n"); return NULL; }

static struct Qdisc_ops onramp_qdisc_ops __read_mostly = {
	.id		=	"onramp",
	.priv_size	=	0,
	.enqueue	=	onramp_enqueue,
	.dequeue	=	onramp_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.owner		=	THIS_MODULE,
};

static int __init onramp_module_init(void) { return register_qdisc(&onramp_qdisc_ops); }

static void __exit onramp_module_exit(void) { unregister_qdisc(&onramp_qdisc_ops); }

module_init(onramp_module_init)
module_exit(onramp_module_exit)
MODULE_LICENSE("GPL");
