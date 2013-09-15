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
#include <net/codel.h>

struct onramp_flow {
	struct sk_buff	  *head;
	struct sk_buff	  *tail;
	struct list_head  flowchain;
	int		  deficit;
	u32		  dropped; /* number of drops (or ECN marks) on this flow */
	struct codel_vars cvars;
}; /* please try to keep this structure <= 64 bytes */

struct onramp_sched_data {
	struct onramp_flow *flows;	/* Flows table [flows_cnt] */
	u32		*backlogs;	/* backlog table [flows_cnt] */
	u32		flows_cnt;	/* number of flows */
	u32		perturbation;	/* hash perturbation */
	u32		quantum;	/* psched_mtu(qdisc_dev(sch)); */
	struct codel_params cparams;
	struct codel_stats cstats;
	u32		drop_overlimit;
	u32		new_flow_count;

	struct list_head new_flows;	/* list of new flows */
	struct list_head old_flows;	/* list of old flows */
};

static unsigned int onramp_hash(const struct onramp_sched_data *q,
				  const struct sk_buff *skb)
{
	struct flow_keys keys;
	unsigned int hash;

	skb_flow_dissect(skb, &keys);
	hash = jhash_3words((__force u32)keys.dst,
			    (__force u32)keys.src ^ keys.ip_proto,
			    (__force u32)keys.ports, q->perturbation);
	return ((u64)hash * q->flows_cnt) >> 32;
}

static unsigned int onramp_classify(struct sk_buff *skb, struct Qdisc *sch,
				      int *qerr)
{
	struct onramp_sched_data *q = qdisc_priv(sch);

	if (TC_H_MAJ(skb->priority) == sch->handle &&
	    TC_H_MIN(skb->priority) > 0 &&
	    TC_H_MIN(skb->priority) <= q->flows_cnt)
		return TC_H_MIN(skb->priority);

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

	codel_set_enqueue_time(skb);
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

/* This is the specific function called from codel_dequeue()
 * to dequeue a packet from queue. Note: backlog is handled in
 * codel, we dont need to reduce it here.
 */
static struct sk_buff *dequeue(struct codel_vars *vars, struct Qdisc *sch)
{
	struct onramp_sched_data *q = qdisc_priv(sch);
	struct onramp_flow *flow;
	struct sk_buff *skb = NULL;

	flow = container_of(vars, struct onramp_flow, cvars);
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
	u32 prev_drop_count, prev_ecn_mark;

	printk("Entering onramp_dequeue\n");
begin:
	head = &q->new_flows;
	if (list_empty(head)) {
		head = &q->old_flows;
		if (list_empty(head))
			return NULL;
	}
	flow = list_first_entry(head, struct onramp_flow, flowchain);

	if (flow->deficit <= 0) {
		flow->deficit += q->quantum;
		list_move_tail(&flow->flowchain, &q->old_flows);
		goto begin;
	}

	prev_drop_count = q->cstats.drop_count;
	prev_ecn_mark = q->cstats.ecn_mark;

	skb = codel_dequeue(sch, &q->cparams, &flow->cvars, &q->cstats,
			    dequeue);

	flow->dropped += q->cstats.drop_count - prev_drop_count;
	flow->dropped += q->cstats.ecn_mark - prev_ecn_mark;

	if (!skb) {
		/* force a pass through old_flows to prevent starvation */
		if ((head == &q->new_flows) && !list_empty(&q->old_flows))
			list_move_tail(&flow->flowchain, &q->old_flows);
		else
			list_del_init(&flow->flowchain);
		goto begin;
	}
	qdisc_bstats_update(sch, skb);
	flow->deficit -= qdisc_pkt_len(skb);
	/* We cant call qdisc_tree_decrease_qlen() if our qlen is 0,
	 * or HTB crashes. Defer it for next round.
	 */
	if (q->cstats.drop_count && sch->q.qlen) {
		qdisc_tree_decrease_qlen(sch, q->cstats.drop_count);
		q->cstats.drop_count = 0;
	}
	printk("Returning a valid skb\n");
	return skb;
}

static void onramp_reset(struct Qdisc *sch)
{
	struct sk_buff *skb;

	while ((skb = onramp_dequeue(sch)) != NULL)
		kfree_skb(skb);
}

static const struct nla_policy onramp_policy[TCA_FQ_CODEL_MAX + 1] = {
	[TCA_FQ_CODEL_TARGET]	= { .type = NLA_U32 },
	[TCA_FQ_CODEL_LIMIT]	= { .type = NLA_U32 },
	[TCA_FQ_CODEL_INTERVAL]	= { .type = NLA_U32 },
	[TCA_FQ_CODEL_ECN]	= { .type = NLA_U32 },
	[TCA_FQ_CODEL_FLOWS]	= { .type = NLA_U32 },
	[TCA_FQ_CODEL_QUANTUM]	= { .type = NLA_U32 },
};

static int onramp_change(struct Qdisc *sch, struct nlattr *opt)
{
	struct onramp_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_FQ_CODEL_MAX + 1];
	int err;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested(tb, TCA_FQ_CODEL_MAX, opt, onramp_policy);
	if (err < 0)
		return err;
	if (tb[TCA_FQ_CODEL_FLOWS]) {
		if (q->flows)
			return -EINVAL;
		q->flows_cnt = nla_get_u32(tb[TCA_FQ_CODEL_FLOWS]);
		if (!q->flows_cnt ||
		    q->flows_cnt > 65536)
			return -EINVAL;
	}
	sch_tree_lock(sch);

	if (tb[TCA_FQ_CODEL_TARGET]) {
		u64 target = nla_get_u32(tb[TCA_FQ_CODEL_TARGET]);

		q->cparams.target = (target * NSEC_PER_USEC) >> CODEL_SHIFT;
	}

	if (tb[TCA_FQ_CODEL_INTERVAL]) {
		u64 interval = nla_get_u32(tb[TCA_FQ_CODEL_INTERVAL]);

		q->cparams.interval = (interval * NSEC_PER_USEC) >> CODEL_SHIFT;
	}

	if (tb[TCA_FQ_CODEL_LIMIT])
		sch->limit = nla_get_u32(tb[TCA_FQ_CODEL_LIMIT]);

	if (tb[TCA_FQ_CODEL_ECN])
		q->cparams.ecn = !!nla_get_u32(tb[TCA_FQ_CODEL_ECN]);

	if (tb[TCA_FQ_CODEL_QUANTUM])
		q->quantum = max(256U, nla_get_u32(tb[TCA_FQ_CODEL_QUANTUM]));

	while (sch->q.qlen > sch->limit) {
		struct sk_buff *skb = onramp_dequeue(sch);

		kfree_skb(skb);
		q->cstats.drop_count++;
	}
	qdisc_tree_decrease_qlen(sch, q->cstats.drop_count);
	q->cstats.drop_count = 0;

	sch_tree_unlock(sch);
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
	INIT_LIST_HEAD(&q->old_flows);
	codel_params_init(&q->cparams);
	codel_stats_init(&q->cstats);
	q->cparams.ecn = true;

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
			codel_vars_init(&flow->cvars);
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
