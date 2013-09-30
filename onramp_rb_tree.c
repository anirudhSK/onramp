#include <linux/rbtree.h>
#include "onramp_rb_tree.h"

/* RB tree functions */
/* Compare function for two onramp_flow_queue structures */
inline int compare_flows(const struct onramp_flow_queue* flow1, const struct onramp_flow_queue* flow2)
{
	if ((flow1->head == NULL) && (flow2->head == NULL)) {
		/* No one wins, both flows are empty */
		return 0;
	} else if (flow1->head == NULL) {
		/* flow1 is greater than flow2 because it is empty */
		return 1;
	} else if (flow2->head == NULL) {
		/* flow1 is lesser than flow2 because flow2 is empty */
		return -1;
	} else if ((flow1->flow_id == flow2->flow_id) &&
		   (flow1->attained_service == flow2->attained_service)) {
		/* flow1 and flow2 are the same, no way to disambiguate */
		return 0;
	} else {
		if (flow1->attained_service > flow2->attained_service) {
			/* flow1 has more service so far */
			return 1;
		} else if (flow1->attained_service < flow2->attained_service) {
			/* flow2 has more service so far */
			return -1;
		} else {
			/* Both flows have equal service */
			if (flow1->flow_id > flow2->flow_id) {
				return 1;
			} else {
				return -1;
			}
		}
	}
}

/* Search function to find onramp_flow_queue inside an rb_tree */
struct onramp_flow_queue* search(struct rb_root *root, struct onramp_flow_queue* candidate)
{
        /* Copied from https://www.kernel.org/doc/Documentation/rbtree.txt */
        struct rb_node *node = root->rb_node;
        while (node) {
                struct onramp_flow_queue* current_ptr = container_of(node, struct onramp_flow_queue, node);
                int result = compare_flows(candidate, current_ptr);

                if (result < 0)
                        node = node->rb_left;
                else if (result > 0)
                        node = node->rb_right;
                else
                        return current_ptr;
        }
        return NULL;
}

/* Remove flow from the RB tree by first searching for it */
/* TODO: What's the return value for remove_flow */
void remove_flow(struct rb_root *root,
                struct onramp_flow_queue* flow_to_remove)
{
	/* Find flow, and remove it */
	struct onramp_flow_queue* search_result = search(root, flow_to_remove);
	if (search_result) {
		rb_erase(&search_result->node, root);
	}
}

/* Insert flow into the RB tree */
int insert_flow(struct rb_root *root, struct onramp_flow_queue* flow_queue)
{
	/* Copied from https://www.kernel.org/doc/Documentation/rbtree.txt */
	struct rb_node **new_pos = &(root->rb_node), *parent = NULL;

	/* Figure out where to put the new node */
	while (*new_pos) {
		struct onramp_flow_queue *current_ptr = container_of(*new_pos, struct onramp_flow_queue, node);
		int result = compare_flows(flow_queue, current_ptr);

                parent = *new_pos;
		if (result < 0) {
			new_pos = &((*new_pos)->rb_left);
                } else if (result > 0) {
                        new_pos = &((*new_pos)->rb_right);
                } else {
                        panic("Flow already exists, shutting down!!\n");
                        return 1;
                }
        }

        /* Add new node and rebalance tree. */
        rb_link_node(&flow_queue->node, parent, new_pos);
        rb_insert_color(&flow_queue->node, root);

        return 0;
}
