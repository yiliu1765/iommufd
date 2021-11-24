// SPDX-License-Identifier: GPL-2.0-only
#include <linux/interval_tree.h>
#include <linux/interval_tree_generic.h>
#include <linux/compiler.h>
#include <linux/export.h>

#define START(node) ((node)->start)
#define LAST(node)  ((node)->last)

INTERVAL_TREE_DEFINE(struct interval_tree_node, rb,
		     unsigned long, __subtree_last,
		     START, LAST,, interval_tree)

EXPORT_SYMBOL_GPL(interval_tree_insert);
EXPORT_SYMBOL_GPL(interval_tree_remove);
EXPORT_SYMBOL_GPL(interval_tree_iter_first);
EXPORT_SYMBOL_GPL(interval_tree_iter_next);

static void
interval_tree_span_iter_next_gap(struct interval_tree_span_iter *state)
{
	struct interval_tree_node *cur = state->nodes[1];

	/*
	 * Roll nodes[1] into nodes[0] by advancing node[1] to the end of a
	 * contiguous span of nodes. This makes nodes[0]->last the end of a
	 * continous span of valid index that started at the original
	 * nodes[1]->start. nodes[1] is now the next node and a hole is between
	 * nodes[0] and [1].
	 */
	state->nodes[0] = cur;
	do {
		if (cur->last > state->nodes[0]->last)
			state->nodes[0] = cur;
		cur = interval_tree_iter_next(cur, state->first_index,
					      state->last_index);
	} while (cur && (state->nodes[0]->last >= cur->start ||
			 state->nodes[0]->last + 1 == cur->start));
	state->nodes[1] = cur;
}


void interval_tree_span_iter_first(struct interval_tree_span_iter *state,
				   struct rb_root_cached *itree,
				   unsigned long index,
				   unsigned long last_index)
{
	state->first_index = index;
	state->last_index = last_index;
	state->nodes[0] = NULL;
	state->nodes[1] = interval_tree_iter_first(itree, index, last_index);
	if (!state->nodes[1]) {
		/* No nodes intersect the span, whole span is hole */
		state->start_hole = index;
		state->last_hole = last_index;
		state->is_hole = 1;
		return;
	}
	if (state->nodes[1]->start > index) {
		/* Leading hole on first iteration */
		state->start_hole = index;
		state->last_hole = state->nodes[1]->start - 1;
		state->is_hole = 1;
		interval_tree_span_iter_next_gap(state);
		return;
	}

	/* Starting inside a used */
	state->start_used = index;
	state->is_hole = 0;
	interval_tree_span_iter_next_gap(state);
	state->last_used = state->nodes[0]->last;
	if (state->last_used >= last_index) {
		state->last_used = last_index;
		state->nodes[0] = NULL;
		state->nodes[1] = NULL;
	}
}
EXPORT_SYMBOL_GPL(interval_tree_span_iter_first);

void interval_tree_span_iter_next(struct interval_tree_span_iter *state)
{
	if (!state->nodes[0] && !state->nodes[1]) {
		state->is_hole = -1;
		return;
	}

	if (state->is_hole) {
		state->start_used = state->last_hole + 1;
		state->last_used = state->nodes[0]->last;
		if (state->last_used >= state->last_index) {
			state->last_used = state->last_index;
			state->nodes[0] = NULL;
			state->nodes[1] = NULL;
		}
		state->is_hole = 0;
		return;
	}

	if (state->nodes[0] && !state->nodes[1]) {
		/* Trailing hole */
		state->start_hole = state->nodes[0]->last + 1;
		state->last_hole = state->last_index;
		state->nodes[0] = NULL;
		state->is_hole = 1;
		return;
	}

	/* must have both nodes[0] and [1], interior hole */
	state->start_hole = state->nodes[0]->last + 1;
	state->last_hole = state->nodes[1]->start - 1;
	state->is_hole = 1;
	interval_tree_span_iter_next_gap(state);
}
EXPORT_SYMBOL_GPL(interval_tree_span_iter_next);
