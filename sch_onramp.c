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
#include <net/ip.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <linux/rbtree.h>
#include "flow_queue.h"

/* QUEUE LIMIT */
#define ONRAMP_LIMIT 10240

/* Structure representing per-client queues */
struct onramp_client_queue {
	int		  empty;		/* Is per-client queue empty? */
	struct onramp_flow_queue *flow_table;   /* per-client flow table */
	struct list_head  pkt_chain;		/* Pointer in linked list of "active_clients" */
	int		  deficit;		/* Deficit counter for DRR */
	u32		  dropped;	        /* number of drops on this client */
	struct rb_root    flow_queue_tree;      /* RB tree of flow queues */
}; /* please try to keep this structure <= 64 bytes */

/* Structure representing aggregate scheduler */
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

/* Pick flow with least attained service from all
   flows belonging to the same client queue */
static int pick_flow_from_client(const struct onramp_sched_data *q,
				 const struct onramp_client_queue *client_queue)
{
	return pick_flow(&client_queue->flow_queue_tree);
}

/* Converse of the above, pick the flow with most
   attained service from all flows belonging to the
   same client queue */
static int pick_most_serviced_flow(const struct onramp_sched_data *q,
				   const struct onramp_client_queue *client_queue)
{
	int i = 0;
	int argmax = -1;
	u64 maxservice = 0;
	printk("maxservice initialized to %llu\n", maxservice);

	for (i = 0; i < q->max_flows; i++) {
		if (client_queue->flow_table[i].head) {
			/* Consider only non-empty flows */
			if (client_queue->flow_table[i].attained_service > maxservice) {
				maxservice = client_queue->flow_table[i].attained_service;
				argmax = i;
			}
		}
	}
	return argmax;
}

/* Hash socket buffer into a flow bin based on
   (src, dst) port pair */
static unsigned int onramp_flow_hash(const struct onramp_sched_data *q,
				     const struct sk_buff *skb)
{
	u32 hash;
	u8 ip_proto;

	switch (skb->protocol) {
	case htons(ETH_P_IP): {
		const struct iphdr *iph = ip_hdr(skb);
		ip_proto = iph->protocol;
		switch (ip_proto) {
		case IPPROTO_TCP: {
			const struct tcphdr *tcph = tcp_hdr(skb);
			hash = jhash_3words(tcph->source, tcph->dest, ip_proto,
					    q->perturbation);
			break;
		}
		case IPPROTO_UDP: {
			const struct udphdr *udph = udp_hdr(skb);
			hash = jhash_3words(udph->source, udph->dest, ip_proto,
					    q->perturbation);
			break;
		}
		default: {
			hash = jhash_3words((unsigned long)skb_dst(skb) ^ skb->protocol,
					    (unsigned long)skb->sk,
					    ip_proto,
					    q->perturbation);
			break;
		}
		}
	}
	default: {
		hash = jhash_3words((unsigned long)skb_dst(skb) ^ skb->protocol,
				    (unsigned long)skb->sk,
				    ip_proto,
				    q->perturbation);
	}
	}
	printk("Flow hash value is %u\n", hash);
	return ((u64)hash * q->max_flows) >> 32;
}

/* Hash socket buffer into a client bin based on
   protocol and dst address */
static unsigned int onramp_client_hash(const struct onramp_sched_data *q,
				       const struct sk_buff *skb)
{
	u32 hash;

	switch (skb->protocol) {
	case htons(ETH_P_IP): {
		const struct iphdr *iph = ip_hdr(skb);
		hash = jhash_2words(iph->saddr, iph->daddr,
			   	    q->perturbation);
		break;
	}
	default: {
		hash = jhash_2words((unsigned long)skb_dst(skb) ^ skb->protocol,		                    (unsigned long)skb->sk,
				    q->perturbation);

	}
	}

	printk("Client hash value is %u\n", hash);
	return ((u64)hash * q->max_clients) >> 32;
}

/* Remove one skb from client */
static inline struct sk_buff *dequeue_from_client(const struct onramp_sched_data* q,
						  struct onramp_client_queue *client_queue)
{
	int flow_id = pick_flow_from_client(q, client_queue);
	if (flow_id == -1) {
		printk("No packets to send\n");
		return NULL;
	}
	printk("Dequeuing from flow_id %d\n", flow_id);
	struct sk_buff* skb = dequeue_from_flow(&client_queue->flow_queue_tree,
						&client_queue->flow_table[flow_id]);
	/* Check all flows to see if the queue is now empty */
	/* At this point, rb-tree is populated iff
	   at least one flow queue is non-empty */
	if (rb_first(&client_queue->flow_queue_tree) != NULL) {
		client_queue->empty = 0; /* Not empty */
	} else {
		client_queue->empty = 1;
	}
	return skb;
}

/* Remove and drop one skb from most serviced flow */
static inline struct sk_buff *drop_from_most_serviced(const struct onramp_sched_data* q,
						      struct onramp_client_queue *client_queue)
{
	int flow_id = pick_most_serviced_flow(q, client_queue);
	if (flow_id == -1) {
		printk("No packets to drop\n");
		return NULL;
	}
	printk("Dropping from flow_id %d\n", flow_id);
	struct sk_buff* skb = dequeue_from_flow(&client_queue->flow_queue_tree,
						&client_queue->flow_table[flow_id]);
	/* Check all flows to see if the client queue is now empty */
	int i = 0;
	for (i = 0; i < q->max_flows; i++) {
		if (client_queue->flow_table[i].head) {
			/* non-empty */
			client_queue->empty = 0;
			return skb;
		}
	}
	/* All constituent flows are empty */
	client_queue->empty = 1;
	return skb;
}

/* TODO: Continue here */
/* Add skb to client_queue (tail add) */
static inline int enqueue_into_client(const struct onramp_sched_data* q,
				      struct onramp_client_queue *client_queue,
				      struct sk_buff *skb)
{
	unsigned int flow_id = onramp_flow_hash(q, skb) + 1;
	if (flow_id == 0) {
		kfree_skb(skb);
		return 1;
		/* Borrowed from Eric Dumazet's code */
	}
	flow_id--;
	client_queue->empty = 0;
	printk("Enqueuing into flow_id %d\n", flow_id);
	enqueue_into_flow(&client_queue->flow_queue_tree,
			  &client_queue->flow_table[flow_id],
			  skb);
	return 0;
}

/* Drop packet because you are over the buffer limit */
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
	skb = drop_from_most_serviced(q, client_queue);
	len = qdisc_pkt_len(skb);
	q->backlogs[idx] -= len;
	kfree_skb(skb);
	sch->q.qlen--;
	sch->qstats.drops++;
	sch->qstats.backlog -= len;
	client_queue->dropped++;
	return idx;
}

/* Entry point into this module from the Linux Networking stack */
static int onramp_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct onramp_sched_data *q = qdisc_priv(sch);
	unsigned int idx;
	struct onramp_client_queue *client_queue;
	int uninitialized_var(ret);
	idx = onramp_client_hash(q, skb) + 1;

	if (idx == 0) {
		/* TODO: Understand this code */
		if (ret & __NET_XMIT_BYPASS)
			sch->qstats.drops++;
		kfree_skb(skb);
		return ret;
	}
	idx--;

	printk("idx on enqueue is %d\n", idx);
	client_queue = &q->queue_table[idx];
	if (enqueue_into_client(q, client_queue, skb)) {
		return 1;
	}
	q->backlogs[idx] += qdisc_pkt_len(skb);
	sch->qstats.backlog += qdisc_pkt_len(skb);

	if (list_empty(&client_queue->pkt_chain)) {
		/* client_queue->pkt_chain isn't part of any list */
		list_add_tail(&client_queue->pkt_chain, &q->active_clients);
		q->clients_so_far++;
		client_queue->deficit = q->quantum;
		client_queue->dropped = 0;
		client_queue->empty   = 0;
	}
	if (++sch->q.qlen <= ONRAMP_LIMIT)
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

	if (!client_queue->empty) {
		skb = dequeue_from_client(q, client_queue);
		q->backlogs[client_queue - q->queue_table] -= qdisc_pkt_len(skb);
		sch->q.qlen--;
	}
	return skb;
}

/* Entry point in this module for the network interface:
   Network interface dequeues in this function */
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
	client_queue->deficit -= qdisc_pkt_len(skb);
	/* We cant call qdisc_tree_decrease_qlen() if our qlen is 0,
	 * or HTB crashes. Defer it for next round.
	 */
	/* Anirudh: TODO Do we need to call qdisc_tree_decrease_qlen()? */

	printk("Returning a valid skb\n");
	return skb;
}

/* reset function borrowed from old code */
static void onramp_reset(struct Qdisc *sch)
{
	struct sk_buff *skb;

	while ((skb = onramp_dequeue(sch)) != NULL)
		kfree_skb(skb);
}

/* Entry point in the module when userspace calls tc qdisc change */
static int onramp_change(struct Qdisc *sch, struct nlattr *opt)
{
	printk("Inside onramp_change, ignoring all requests for change\n");
	return 0;
}

static void *onramp_zalloc(size_t sz)
{
	void *ptr = kzalloc(sz, GFP_KERNEL | __GFP_NOWARN);
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

/* Entry point in the module when userspace calls tc qdisc add */
static int onramp_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct onramp_sched_data *q = qdisc_priv(sch);
	int i, j;

	q->max_clients = 64;
	q->max_flows   = 64;
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
			client_queue->flow_table = onramp_zalloc(q->max_flows * sizeof(struct onramp_flow_queue));
			if (!client_queue->flow_table) {
				onramp_free(client_queue->flow_table);
				return -ENOMEM;
			}
			for (j = 0; j < q->max_flows; j++) {
			        client_queue->flow_table[j].head = NULL;
			        client_queue->flow_table[j].tail = NULL;
			        client_queue->flow_table[j].attained_service = 0;
			        client_queue->flow_table[j].flow_id = j;
			}
			client_queue->flow_queue_tree = RB_ROOT;
			client_queue->empty = 1;
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
