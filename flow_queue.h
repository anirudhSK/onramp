#ifndef FLOW_QUEUE_H_
#define FLOW_QUEUE_H_

#include <linux/rbtree.h>

struct onramp_flow_queue {
	struct sk_buff	  *head;
	struct sk_buff	  *tail;
	u64		  attained_service;
	struct rb_node    node;
	u16		  flow_id;
}; /* please try to keep this structure <= 64 bytes */

/* Helper functions : might be changed when/if skb use a standard list_head */
/* Dequeue from flow */
inline struct sk_buff *dequeue_from_flow(struct rb_root* flow_queue_tree,
					 struct onramp_flow_queue *flow_queue);

/* Add to flow queue */
inline void enqueue_into_flow(struct rb_root* flow_queue_tree,
			      struct onramp_flow_queue *flow_queue,
			      struct sk_buff *skb);

/* Pick LAS flow */
u16 pick_flow(const struct rb_root *root);

inline void iterate(struct rb_root* rb_tree);
#endif  // FLOW_QUEUE_H_
