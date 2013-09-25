#ifndef ONRAMP_RB_TREE_H_
#define ONRAMP_RB_TREE_H_

#include "flow_queue.h"

/* Compare function for two onramp_flow_queue structures */
inline int compare_flows(const struct onramp_flow_queue* flow1, const struct onramp_flow_queue* flow2);

/* Search function to find onramp_flow_queue inside an rb_tree */
struct onramp_flow_queue* search(struct rb_root *root, struct onramp_flow_queue* candidate);

/* Remove flow from the RB tree by first searching for it */
/* TODO: What's the return value for remove_flow */
void remove_flow(struct rb_root *root,
                struct onramp_flow_queue* flow_to_remove);

/* Insert flow into the RB tree */
int insert_flow(struct rb_root *root, struct onramp_flow_queue* flow_queue);

#endif  // ONRAMP_RB_TREE_H_
