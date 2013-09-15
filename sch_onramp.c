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

struct onramp_client_queue {
	struct sk_buff	  *head;
	struct sk_buff	  *tail;
	struct list_head  pkt_chain;
	int		  deficit;
	u32		  dropped; /* number of drops on this client */
}; /* please try to keep this structure <= 64 bytes */

struct onramp_sched_data {
	struct onramp_client_queue *queue_table;/* Client queues table [max_clients] */
	u32		*backlogs;		/* backlog table [max_clients] */
	u32		max_clients;		/* maximum number of clients */
	u32		max_flows;		/* maximum number of flows per client */
	u32		perturbation;		/* hash perturbation */
	u32		quantum;		/* psched_mtu(qdisc_dev(sch)); */
	u32		drop_overlimit;		/* Number of packets dropped due to queue overflow */
	u32		clients_so_far;		/* Total number of clients seen so far */

	struct list_head active_clients;	/* list of currently active clients */
};

static unsigned int onramp_flow_hash(const struct onramp_sched_data *q,
				     const struct sk_buff *skb)
{
	struct flow_keys keys;
	unsigned int hash;

	skb_flow_dissect(skb, &keys);
	hash = jhash_2words((__force u32)keys.ports,
			    (__force u32)keys.ip_proto,
			    q->perturbation);
	printk("Flow hash value is %u\n", hash);
	return ((u64)hash * q->max_flows) >> 32;
}

static unsigned int onramp_client_hash(const struct onramp_sched_data *q,
				       const struct sk_buff *skb)
{
	struct flow_keys keys;
	unsigned int hash;

	skb_flow_dissect(skb, &keys);
	hash = jhash_2words((__force u32)keys.dst,
			    (__force u32)keys.ip_proto,
			    q->perturbation);
	printk("Client hash value is %u\n", hash);
	return ((u64)hash * q->max_clients) >> 32;
}

/* helper functions : might be changed when/if skb use a standard list_head */

/* remove one skb from head of slot queue */
static inline struct sk_buff *dequeue_head(struct onramp_client_queue *client_queue)
{
	struct sk_buff *skb = client_queue->head;

	client_queue->head = skb->next;
	skb->next = NULL;
	return skb;
}

/* add skb to client_queue (tail add) */
static inline void client_queue_add(struct onramp_client_queue *client_queue,
				    struct sk_buff *skb)
{
	if (client_queue->head == NULL)
		client_queue->head = skb;
	else
		client_queue->tail->next = skb;
	client_queue->tail = skb;
	skb->next = NULL;
}

static unsigned int onramp_drop(struct Qdisc *sch)
{
	struct onramp_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	unsigned int maxbacklog = 0, idx = 0, i, len;
	struct onramp_client_queue *client_queue;

	/* Queue is full! Find the fat client and drop packet from it.
	 * This might sound expensive, but with 1024 queues, we scan
	 * 4KB of memory, and we dont need to handle a complex tree
	 * in fast path (packet queue/enqueue) with many cache misses.
	 */
	for (i = 0; i < q->max_clients; i++) {
		if (q->backlogs[i] > maxbacklog) {
			maxbacklog = q->backlogs[i];
			idx = i;
		}
	}
	client_queue = &q->queue_table[idx];
	skb = dequeue_head(client_queue);
	len = qdisc_pkt_len(skb);
	q->backlogs[idx] -= len;
	kfree_skb(skb);
	sch->q.qlen--;
	sch->qstats.drops++;
	sch->qstats.backlog -= len;
	client_queue->dropped++;
	return idx;
}

static int onramp_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct onramp_sched_data *q = qdisc_priv(sch);
	unsigned int idx;
	struct onramp_client_queue *client_queue;
	int uninitialized_var(ret);
	idx = onramp_client_hash(q, skb) + 1;

	printk("idx on enqueue is %d\n", idx);
	if (idx == 0) {
		if (ret & __NET_XMIT_BYPASS)
			sch->qstats.drops++;
		kfree_skb(skb);
		return ret;
	}
	idx--;

	client_queue = &q->queue_table[idx];
	client_queue_add(client_queue, skb);
	q->backlogs[idx] += qdisc_pkt_len(skb);
	sch->qstats.backlog += qdisc_pkt_len(skb);

	if (list_empty(&client_queue->pkt_chain)) {
		list_add_tail(&client_queue->pkt_chain, &q->active_clients);
		q->clients_so_far++;
		client_queue->deficit = q->quantum;
		client_queue->dropped = 0;
	}
	if (++sch->q.qlen <= sch->limit)
		return NET_XMIT_SUCCESS;

	q->drop_overlimit++;
	/* Return Congestion Notification only if we dropped a packet
	 * from this client_queue.
	 */
	if (onramp_drop(sch) == idx)
		return NET_XMIT_CN;

	/* As we dropped a packet, better let upper stack know this */
	qdisc_tree_decrease_qlen(sch, 1);
	return NET_XMIT_SUCCESS;
}

/* This is the function to dequeue a packet from a specific client_queue.
 * Anirudh: Qdisc::backlog was handled in codel, but we are ignoring it completely.
 */
static struct sk_buff *dequeue_from_client_queue(struct Qdisc *sch, struct onramp_client_queue* client_queue)
{
	struct onramp_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb = NULL;

	if (client_queue->head) {
		skb = dequeue_head(client_queue);
		q->backlogs[client_queue - q->queue_table] -= qdisc_pkt_len(skb);
		sch->q.qlen--;
	}
	return skb;
}

static struct sk_buff *onramp_dequeue(struct Qdisc *sch)
{
	struct onramp_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	struct onramp_client_queue *client_queue;
	struct list_head *head;

	printk("Entering onramp_dequeue\n");
begin:
	head = &q->active_clients;
	if (list_empty(head)) {
		return NULL;
	}
	client_queue = list_first_entry(head, struct onramp_client_queue, pkt_chain);

	if (client_queue->deficit <= 0) {
		client_queue->deficit += q->quantum;
		list_move_tail(&client_queue->pkt_chain, &q->active_clients);
		goto begin;
	}


	skb = dequeue_from_client_queue(sch, client_queue);

	/* Anirudh: client_queue->dropped doesn't need to be updated
	   because we no longer drop here */

	if (!skb) {
		/* Remove the client_queue from the list */
		list_del_init(&client_queue->pkt_chain);
		goto begin;
	}
	qdisc_bstats_update(sch, skb);
	client_queue->deficit -= qdisc_pkt_len(skb);
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
	onramp_free(q->queue_table);
}

static int onramp_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct onramp_sched_data *q = qdisc_priv(sch);
	int i;

	sch->limit = 10*1024;
	q->max_clients = 1024;
	q->max_flows   = 1024;
	q->quantum = psched_mtu(qdisc_dev(sch));
	q->perturbation = net_random();
	INIT_LIST_HEAD(&q->active_clients);

	if (opt) {
		int err = onramp_change(sch, opt);
		if (err)
			return err;
	}

	if (!q->queue_table) {
		q->queue_table = onramp_zalloc(q->max_clients *
					   sizeof(struct onramp_client_queue));
		if (!q->queue_table)
			return -ENOMEM;
		q->backlogs = onramp_zalloc(q->max_clients * sizeof(u32));
		if (!q->backlogs) {
			onramp_free(q->queue_table);
			return -ENOMEM;
		}
		for (i = 0; i < q->max_clients; i++) {
			struct onramp_client_queue *client_queue = q->queue_table + i;

			INIT_LIST_HEAD(&client_queue->pkt_chain);
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
