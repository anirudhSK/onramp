struct onramp_flow_queue {
	struct sk_buff	  *head;
	struct sk_buff	  *tail;
	int		  attained_service;
	u32		  dropped;	       /* number of drops on this flow */
}; /* please try to keep this structure <= 64 bytes */

/* Helper functions : might be changed when/if skb use a standard list_head */
/* Dequeue from flow */
inline struct sk_buff *dequeue_from_flow(struct onramp_flow_queue *flow_queue)
{
	/* TODO: Appropriately adjust Las */
	struct sk_buff *skb = flow_queue->head;
	flow_queue->head = skb->next;
	skb->next = NULL;
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
