#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/flow_keys.h>

struct onramp_flow {
	struct sk_buff	  *head;
	struct sk_buff	  *tail;
	struct list_head  flowchain;
	int		  deficit;
	u32		  dropped; /* number of drops (or ECN marks) on this flow */
}; /* please try to keep this structure <= 64 bytes */

struct onramp_sched_data {
	struct onramp_flow *flows;	/* Flows table [flows_cnt] */
	u32		*backlogs;	/* backlog table [flows_cnt] */
	u32		flows_cnt;	/* number of flows */
	u32		perturbation;	/* hash perturbation */
	u32		quantum;	/* psched_mtu(qdisc_dev(sch)); */
	u32		drop_overlimit;
	u32		new_flow_count;

	struct list_head new_flows;	/* list of new flows */
};

static unsigned int onramp_hash(const struct onramp_sched_data *q,
				  const struct sk_buff *skb)
{
	struct flow_keys keys;
	unsigned int hash;

	skb_flow_dissect(skb, &keys);
	hash = jhash_2words((__force u32)keys.dst,
			    (__force u32)keys.ip_proto,
			    q->perturbation);
	return ((u64)hash * q->flows_cnt) >> 32;
}

static unsigned int onramp_classify(struct sk_buff *skb, struct Qdisc *sch,
				      int *qerr)
{
	struct onramp_sched_data *q = qdisc_priv(sch);
	return onramp_hash(q, skb) + 1;
}

/* helper functions : might be changed when/if skb use a standard list_head */

/* remove one skb from head of slot queue */
static inline struct sk_buff *dequeue_head(struct onramp_flow *flow)
{
	struct sk_buff *skb = flow->head;

	flow->head = skb->next;
	skb->next = NULL;
	return skb;
}

/* add skb to flow queue (tail add) */
static inline void flow_queue_add(struct onramp_flow *flow,
				  struct sk_buff *skb)
{
	if (flow->head == NULL)
		flow->head = skb;
	else
		flow->tail->next = skb;
	flow->tail = skb;
	skb->next = NULL;
}

static unsigned int onramp_drop(struct Qdisc *sch)
{
	struct onramp_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	unsigned int maxbacklog = 0, idx = 0, i, len;
	struct onramp_flow *flow;

	/* Queue is full! Find the fat flow and drop packet from it.
	 * This might sound expensive, but with 1024 flows, we scan
	 * 4KB of memory, and we dont need to handle a complex tree
	 * in fast path (packet queue/enqueue) with many cache misses.
	 */
	for (i = 0; i < q->flows_cnt; i++) {
		if (q->backlogs[i] > maxbacklog) {
			maxbacklog = q->backlogs[i];
			idx = i;
		}
	}
	flow = &q->flows[idx];
	skb = dequeue_head(flow);
	len = qdisc_pkt_len(skb);
	q->backlogs[idx] -= len;
	kfree_skb(skb);
	sch->q.qlen--;
	sch->qstats.drops++;
	sch->qstats.backlog -= len;
	flow->dropped++;
	return idx;
}

static int onramp_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct onramp_sched_data *q = qdisc_priv(sch);
	unsigned int idx;
	struct onramp_flow *flow;
	int uninitialized_var(ret);

	idx = onramp_classify(skb, sch, &ret);
	if (idx == 0) {
		if (ret & __NET_XMIT_BYPASS)
			sch->qstats.drops++;
		kfree_skb(skb);
		return ret;
	}
	idx--;

	flow = &q->flows[idx];
	flow_queue_add(flow, skb);
	q->backlogs[idx] += qdisc_pkt_len(skb);
	sch->qstats.backlog += qdisc_pkt_len(skb);

	if (list_empty(&flow->flowchain)) {
		list_add_tail(&flow->flowchain, &q->new_flows);
		q->new_flow_count++;
		flow->deficit = q->quantum;
		flow->dropped = 0;
	}
	if (++sch->q.qlen <= sch->limit)
		return NET_XMIT_SUCCESS;

	q->drop_overlimit++;
	/* Return Congestion Notification only if we dropped a packet
	 * from this flow.
	 */
	if (onramp_drop(sch) == idx)
		return NET_XMIT_CN;

	/* As we dropped a packet, better let upper stack know this */
	qdisc_tree_decrease_qlen(sch, 1);
	return NET_XMIT_SUCCESS;
}

/* This is the function to dequeue a packet from a specific flow.
 * Anirudh: Qdisc::backlog was handled in codel, but we are ignoring it completely.
 */
static struct sk_buff *dequeue_from_flow(struct Qdisc *sch, struct onramp_flow* flow)
{
	struct onramp_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb = NULL;

	if (flow->head) {
		skb = dequeue_head(flow);
		q->backlogs[flow - q->flows] -= qdisc_pkt_len(skb);
		sch->q.qlen--;
	}
	return skb;
}

static struct sk_buff *onramp_dequeue(struct Qdisc *sch)
{
	struct onramp_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	struct onramp_flow *flow;
	struct list_head *head;

	printk("Entering onramp_dequeue\n");
begin:
	head = &q->new_flows;
	if (list_empty(head)) {
		return NULL;
	}
	flow = list_first_entry(head, struct onramp_flow, flowchain);

	if (flow->deficit <= 0) {
		flow->deficit += q->quantum;
		list_move_tail(&flow->flowchain, &q->new_flows);
		goto begin;
	}


	skb = dequeue_from_flow(sch, flow);

	/* Anirudh: flow->dropped doesn't need to be updated
	   because we no longer drop here */

	if (!skb) {
		/* Remove the flow from the list */
		list_del_init(&flow->flowchain);
		goto begin;
	}
	qdisc_bstats_update(sch, skb);
	flow->deficit -= qdisc_pkt_len(skb);
	/* We cant call qdisc_tree_decrease_qlen() if our qlen is 0,
	 * or HTB crashes. Defer it for next round.
	 */
	/* Anirudh: Do we need to call qdisc_tree_decrease_qlen()? */

	printk("Returning a valid skb\n");
	return skb;
}

static void onramp_reset(struct Qdisc *sch)
{
	struct sk_buff *skb;

	while ((skb = onramp_dequeue(sch)) != NULL)
		kfree_skb(skb);
}

static int onramp_change(struct Qdisc *sch, struct nlattr *opt)
{
	printk("Inside onramp_change, ignoring all requests for change\n");
	return 0;
}

static void *onramp_zalloc(size_t sz)
{
	void *ptr = kzalloc(sz, GFP_KERNEL | __GFP_NOWARN);

	if (!ptr)
		ptr = vzalloc(sz);
	return ptr;
}

static void onramp_free(void *addr)
{
	if (addr) {
		if (is_vmalloc_addr(addr))
			vfree(addr);
		else
			kfree(addr);
	}
}

static void onramp_destroy(struct Qdisc *sch)
{
	struct onramp_sched_data *q = qdisc_priv(sch);

	onramp_free(q->backlogs);
	onramp_free(q->flows);
}

static int onramp_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct onramp_sched_data *q = qdisc_priv(sch);
	int i;

	sch->limit = 10*1024;
	q->flows_cnt = 1024;
	q->quantum = psched_mtu(qdisc_dev(sch));
	q->perturbation = net_random();
	INIT_LIST_HEAD(&q->new_flows);

	if (opt) {
		int err = onramp_change(sch, opt);
		if (err)
			return err;
	}

	if (!q->flows) {
		q->flows = onramp_zalloc(q->flows_cnt *
					   sizeof(struct onramp_flow));
		if (!q->flows)
			return -ENOMEM;
		q->backlogs = onramp_zalloc(q->flows_cnt * sizeof(u32));
		if (!q->backlogs) {
			onramp_free(q->flows);
			return -ENOMEM;
		}
		for (i = 0; i < q->flows_cnt; i++) {
			struct onramp_flow *flow = q->flows + i;

			INIT_LIST_HEAD(&flow->flowchain);
		}
	}

	/* Anirudh: Cannot bypass at any cost */
	sch->flags &= ~TCQ_F_CAN_BYPASS;
	return 0;
}

static struct Qdisc_ops onramp_qdisc_ops __read_mostly = {
	.id		=	"onramp",
	.priv_size	=	sizeof(struct onramp_sched_data),
	.enqueue	=	onramp_enqueue,
	.dequeue	=	onramp_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.drop		=	onramp_drop,
	.init		=	onramp_init,
	.reset		=	onramp_reset,
	.destroy	=	onramp_destroy,
	.change		=	onramp_change,
	.owner		=	THIS_MODULE,
};

static int __init onramp_module_init(void)
{
	return register_qdisc(&onramp_qdisc_ops);
}

static void __exit onramp_module_exit(void)
{
	unregister_qdisc(&onramp_qdisc_ops);
}

module_init(onramp_module_init)
module_exit(onramp_module_exit)
MODULE_AUTHOR("Eric Dumazet");
MODULE_LICENSE("GPL");
