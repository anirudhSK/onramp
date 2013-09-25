struct onramp_flow_queue {
	struct sk_buff	  *head;
	struct sk_buff	  *tail;
	u64		  attained_service;
}; /* please try to keep this structure <= 64 bytes */

/* Helper functions : might be changed when/if skb use a standard list_head */
/* Dequeue from flow */
inline struct sk_buff *dequeue_from_flow(struct onramp_flow_queue *flow_queue)
{
	struct sk_buff *skb = flow_queue->head;
	flow_queue->head = skb->next;
	flow_queue->attained_service += qdisc_pkt_len(skb);
	skb->next = NULL;
	if (flow_queue->head == NULL) {
		/* Reset Attained service */
		printk("Resetting attained service here\n");
		flow_queue->attained_service = 0;
	}
	return skb;
}

/* Add to flow queue */
inline void enqueue_into_flow(struct onramp_flow_queue *flow_queue,
			      struct sk_buff *skb)
{
	if (flow_queue->head == NULL)
		flow_queue->head = skb;
	else
		flow_queue->tail->next = skb;
	flow_queue->tail = skb;
	skb->next = NULL;
}
