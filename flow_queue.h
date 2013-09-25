#ifndef FLOW_QUEUE_H_
#define FLOW_QUEUE_H_

struct onramp_flow_queue {
	struct sk_buff	  *head;
	struct sk_buff	  *tail;
	u64		  attained_service;
}; /* please try to keep this structure <= 64 bytes */

/* Helper functions : might be changed when/if skb use a standard list_head */
/* Dequeue from flow */
inline struct sk_buff *dequeue_from_flow(struct onramp_flow_queue *flow_queue);

/* Add to flow queue */
inline void enqueue_into_flow(struct onramp_flow_queue *flow_queue,
			      struct sk_buff *skb);

#endif  // FLOW_QUEUE_H_
