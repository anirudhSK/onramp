#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>
#include "onramp_rb_tree.h"
#include "flow_queue.h"

/* Helper functions : might be changed when/if skb use a standard list_head */
/* Dequeue from flow */
inline struct sk_buff *dequeue_from_flow(struct rb_root* flow_queue_tree,
					 struct onramp_flow_queue *flow_queue)
{
	/* Remove flow from RB tree before doing anything else */
	remove_flow(flow_queue_tree, flow_queue);

	struct sk_buff *skb = flow_queue->head;
	flow_queue->head = skb->next;
	flow_queue->attained_service += qdisc_pkt_len(skb);
	skb->next = NULL;
	if (flow_queue->head == NULL) {
		/* Reset Attained service */
		printk("Resetting attained service here\n");
		flow_queue->attained_service = 0;
	} else {
		/* Reinsert flow into RB tree */
		insert_flow(flow_queue_tree, flow_queue);
	}

	return skb;
}

/* Add to flow queue */
inline void enqueue_into_flow(struct rb_root* flow_queue_tree,
			      struct onramp_flow_queue *flow_queue,
			      struct sk_buff *skb)
{
	if (flow_queue->head == NULL) {
		flow_queue->head = skb;
		/* Enqueueing an empty flow, insert into RB tree */
		flow_queue->attained_service = 0;
		insert_flow(flow_queue_tree, flow_queue);
	} else {
		flow_queue->tail->next = skb;
	}
	flow_queue->tail = skb;
	skb->next = NULL;
}

/* Pick LAS flow */
u16 pick_flow(const struct rb_root *root)
{
        return (container_of(rb_first(root), struct onramp_flow_queue, node)->flow_id);
}
