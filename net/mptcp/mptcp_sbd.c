
#include <net/mptcp.h>
#include <linux/sort.h>

// implemented in mptcp_input.c
int mptcp_fill_snapshots_until(struct tcp_sock *tp, int cur_index);

struct mptcp_flow_stats {
  s64 mean, variance, skewness, keyfreq, losses, lossrate;
  int pi, count, previously_congested;
};

static void process_subflow(struct mptcp_flow_stats* result, int next_index,
                            const struct mptcp_owd_snapshot *data) {
    int i;

    s64 mean, variance;
    int crossings, last_region;
    s64 interval_width, kf_low, kf_high;
    
    s64 mean_sum      = 0;
    s64 mad_var_sum   = 0;
    s64 skewness_base = 0;
    int chunk_count   = 0;
    int sample_count  = 0;
    s64 loss_count    = 0;

    for (i = 0; i < SBD_N_1; ++i) {
        s64 local_mean;
        s64 local_skewness_base;
        const struct mptcp_owd_snapshot* chunk;
        
        chunk = &data[i];
        if (chunk->count == 0 || chunk->index == next_index) {
            continue; // skip, no data or not finished
        }

        chunk_count  += 1;
        sample_count += chunk->count;
        loss_count   += chunk->loss_count;

        local_mean     = div_s64(chunk->sum_usecs, chunk->count);
        local_skewness_base = chunk->skew_lcount - chunk->skew_rcount;
        
        mean_sum      += local_mean;
        mad_var_sum   += chunk->mad_var_sum;
        skewness_base += local_skewness_base;
    }

    result->count  = sample_count;
    result->losses = loss_count;
    if (sample_count == 0) {
      // all null, avoid division by zero below
      result->mean     = 0;
      result->variance = 0;
      result->skewness = 0;
      result->keyfreq  = 0;
      result->lossrate = 0;
      return;
    }

    mean     = div_s64(mean_sum,    chunk_count);
    variance = div_s64(mad_var_sum, sample_count * 8); // mad var sum is shifted left by 3

    result->mean     = mean;
    result->variance = variance;
    result->skewness = div_s64(skewness_base * 1000, sample_count);
    result->lossrate = div_s64(loss_count * 100000,  sample_count);

    crossings = 0;
    last_region = 2;
    interval_width = div_s64(variance * 7, 10); // PV=0.7
    kf_low  = mean - interval_width;
    kf_high = mean + interval_width;
    for (i = 0; i < SBD_N_1; ++i) {
        // need to traverse oldest to newest!
        // the one after the next_index is the oldest
        int idx = (next_index + 1 + i) % SBD_N_1;

        int region;
        s64 local_mean;
        s64 local_skewness_base;
        s64 local_skewness;
        const struct mptcp_owd_snapshot* chunk;

        chunk = &data[idx];
        if (chunk->count == 0 || chunk->index == next_index) {
            continue; // skip, no data or not finished
        }

        local_mean     = div_s64(chunk->sum_usecs,           chunk->count);
        local_skewness_base = chunk->skew_lcount - chunk->skew_rcount;
        local_skewness = div_s64(local_skewness_base * 1000, chunk->count);

        if (local_mean > kf_high) {
            region = 1;
        }
        else if (local_mean < kf_low) {
            region = -1;
        }
        else {
            region = 0;
        }
        
        if (last_region == 2) {
            last_region = region;
            continue;
        }
        
        //if ((last_region == 1 && region == -1) || (last_region == -1 && region == 1)) {
        if (last_region != region && (region == -1 || region == 1)) {
            if (true || local_skewness < -10) { // c_s=-0.01, local_skewness is scaled by 1000, TODO: should we also consider previous congestion?, NOTE: disabled by David
                // only record a significant mean crossing if flow is experiencing congestion
                crossings += 1;
            }
            last_region = region; // TODO: next to crossings += 1?
        }
    }

    result->keyfreq  = (crossings * 1000) / chunk_count;
}

void print_flow_stats(int group_id, const struct mptcp_flow_stats* stats) {
    printk(KERN_ERR "SBD-INFO %i. pi=% 2i mean=%i var=%i skew=%i keyf=%i loss=%i%% samples=%i\n",
        group_id, stats->pi,
        (int)div_s64(stats->mean, 1000), (int)div_s64(stats->variance, 1000),
        (int)stats->skewness, (int)stats->keyfreq,
        (int)div_s64(stats->lossrate, 1000),
        stats->count);
}

void swap_stats(void* a, void* b, int size) {
    struct mptcp_flow_stats tmp;
    if (a == b)
        return;

    memcpy(&tmp, a, sizeof(tmp));
    memcpy(a,    b, sizeof(tmp));
    memcpy(b, &tmp, sizeof(tmp));
}

int is_flow_congested(const struct mptcp_flow_stats* s) {
    if (s->skewness < -10) { // c_s=-0.01, skewness is scaled by 1000
        return 1;
    }
    else if (s->skewness < 300 && s->previously_congested) { // c_h=0.3, skewness is scaled by 1000
        return 1;
    }
    else if (s->losses * 10 >= s->count) { // p_l=0.1, i.e. 10%
        return 1;
    }
    return 0;
}

int split_congestion(struct mptcp_flow_stats* stats, int num_flows) {
    int i = 0, e = num_flows - 1;
    
    while (i <= e) {
        if (is_flow_congested(&stats[i])) {
            i++;
        }
        else {
            // swap with the one at the tail
            swap_stats(&stats[i], &stats[e], sizeof(struct mptcp_flow_stats));
            e--;
        }
    }
    
    return i;
}

int cmp_stats_keyfreq(const void* a, const void* b)
{
    const struct mptcp_flow_stats* sa = a;
    const struct mptcp_flow_stats* sb = b;
    return sb->keyfreq - sa->keyfreq; // reversed for descending sort
}

int cmp_stats_variance(const void* a, const void* b)
{
    const struct mptcp_flow_stats* sa = a;
    const struct mptcp_flow_stats* sb = b;
    return sb->variance - sa->variance; // reversed for descending sort
}

int cmp_stats_skewness(const void* a, const void* b)
{
    const struct mptcp_flow_stats* sa = a;
    const struct mptcp_flow_stats* sb = b;
    return sb->skewness - sa->skewness; // reversed for descending sort
}

int cmp_stats_lossrate(const void* a, const void* b)
{
    const struct mptcp_flow_stats* sa = a;
    const struct mptcp_flow_stats* sb = b;
    return sb->lossrate - sa->lossrate; // reversed for descending sort
}

int has_high_losses(const struct mptcp_flow_stats* stats, int begin, int end) {
    int i;
    for (i = begin; i < end; ++i) {
        const struct mptcp_flow_stats* s = &stats[i];
        if (s->losses * 10 >= s->count) { // p_l=0.1, i.e. 10%
            return 1;
        }
    }
    return 0;
}

// p_mad = 0.1, relative
int is_grouped_variance(s64 high_var, s64 low_var) {
    return (high_var - low_var) * 10 < high_var;
}

// p_d = 0.1, relative
int is_grouped_lossrate(s64 high_loss, s64 low_loss) {
    return (high_loss - low_loss) * 10 < high_loss;
}

void store_group(struct mptcp_sbd_observation* obs, struct mptcp_flow_stats* stats, int begin, int end, int non_congested) {
    int i;

    if (!non_congested)
        obs->text[obs->len++] = ';'; // end last group

    for (i = begin; i < end; ++i) {
        obs->text[obs->len++] = 'A' + (stats[i].pi - 1); // map pi=1 to A, pi=2 to B, etc.
    }

    obs->text[obs->len] = 0; // terminate string

    BUG_ON(obs->len > SBD_OBSERVATION_MAX_TEXT_LEN);
}

void finish_group(struct mptcp_sbd_observation* obs, struct mptcp_flow_stats* stats, int begin, int end, int* next_group_id) {
    int i, group_id;

    if (begin >= end) // no flow? done!
        return;

    group_id = (*next_group_id)++;
    for (i = begin; i < end; ++i) {
        print_flow_stats(group_id, &stats[i]);
    }

    store_group(obs, stats, begin, end, 0);
}

// first we split by keyfreq
void split(struct mptcp_sbd_observation *obs, struct mptcp_flow_stats* stats, int begin, int end, int mode, int* next_group_id) {
    int i, group_begin, split_loss;

    if (begin + 1 >= end) { // no or only one flow? done!
        finish_group(obs, stats, begin, end, next_group_id);
        return;    
    }

    split_loss = (mode == 2 && has_high_losses(stats, begin, end)); // Skewness or Loss?

    if (mode == 0) {
        // Bottleneck frequency
        sort(&stats[begin], end - begin, sizeof(struct mptcp_flow_stats),
             cmp_stats_keyfreq, swap_stats);
    }
    else if (mode == 1) {
        // PDV
        sort(&stats[begin], end - begin, sizeof(struct mptcp_flow_stats),
             cmp_stats_variance, swap_stats);
    }
    else if (mode == 2) {
        if (split_loss) {
            // Loss
            sort(&stats[begin], end - begin, sizeof(struct mptcp_flow_stats),
                 cmp_stats_lossrate, swap_stats);
        }
        else {
            // Skewness
            sort(&stats[begin], end - begin, sizeof(struct mptcp_flow_stats),
                 cmp_stats_skewness, swap_stats);            
        }
    }
    else {
        finish_group(obs, stats, begin, end, next_group_id);
        return;   
    }
    
    group_begin = begin;
    for (i = begin + 1; i < end; ++i) {
        // Bottleneck frequency
        if (mode == 0 && stats[i-1].keyfreq - stats[i].keyfreq < 100) { // p_f = 0.1, absolute
            continue;
        }
        // PDV
        else if (mode == 1 && is_grouped_variance(stats[i-1].variance, stats[i].variance)) {
            continue;
        }
        // Skewness
        else if (mode == 2 && !split_loss && stats[i-1].skewness - stats[i].skewness < 100) { // p_s = 0.1, absolute
            continue;
        }
        // Loss instead of Skewness
        else if (mode == 2 &&  split_loss && is_grouped_lossrate(stats[i-1].lossrate, stats[i].lossrate)) {
            continue;
        }
        else {
						if (mode == 0)
							printk(KERN_ERR "SBD-SPLIT keyfreq\n");
						else if (mode == 1)
							printk(KERN_ERR "SBD-SPLIT variance\n");
						else if (mode == 2 && !split_loss)
							printk(KERN_ERR "SBD-SPLIT skewness\n");
						else if (mode == 2 && split_loss)
							printk(KERN_ERR "SBD-SPLIT loss\n");

            // do not belong to the same group!
            // process the group we built and start a new one
            split(obs, stats, group_begin, i, mode + 1, next_group_id);
            group_begin = i; // start a new group
        }
    }
    split(obs, stats, group_begin, end, mode + 1, next_group_id);
}

#define MAX_FLOWS 32

void merge_observations(char *flow_groups, const struct mptcp_sbd_observation* obs, int count, int threshold) {
	int idx, oidx, i;
	char next_group_id;

	memset(flow_groups, 0, sizeof(char) * MAX_FLOWS);
	if (count <= 0)
		return;

	next_group_id = 1;
	for (idx = 0; idx < MAX_FLOWS; ++idx) {
		unsigned int together_masks[SBD_MAX_OBSERVATIONS];
		unsigned int present_mask;
		int is_first_group_count;
		char pid;
		char group_id;

		if (flow_groups[idx]) // already part of a group?
			continue;

		present_mask = 0;
		is_first_group_count = 0; // first group is special, means non-congested flows
		pid = 'A' + idx;
		for (i = 0; i < count; ++i) {
			unsigned int *together_mask = &together_masks[i];

			// find group of pid
			const char *o = obs[i].text;
			const char *s = o, *e = 0; // e is inclusive
			int found_start = 0;
			while (*o) {
				if (found_start) {
					if (*o == ';')
						break;
					e = o;
				}
				else {
					if (*o == ';') {
						s = o + 1;
					}
					else if (*o == pid) {
						found_start = 1;
						e = o;
					}
				}
				++o;
			}

			*together_mask = 0;

			if (e) { // if there is no e, the flow is not present in the observation
				if (s == obs[i].text) {
					is_first_group_count++;
				}
				while (s <= e) {
					int idx = (*s - 'A');
					*together_mask |= 1 << idx;
					++s;
				}
				present_mask |= *together_mask;
			}
		}
		
		if (!present_mask)
			continue; // not even the current flow was present in an observation

		// allocate a group for this flow
		if (is_first_group_count >= threshold) {
			group_id = 99;
		}
		else {
			group_id = next_group_id++;			
		}
		flow_groups[idx] = group_id;
		printk(KERN_ERR "SBD-GROUP assigned group: pi:%i -> %i\n", idx+1, group_id);

		// now see how often idx is together with oidx
		for (oidx = idx + 1; oidx < MAX_FLOWS; ++oidx) {
			unsigned int omask = 1 << oidx;
			if (present_mask & omask) {
				// count how often the other flow was together with the current flow
				int together_count = 0;
				for (i = 0; i < count; ++i) {
					if (together_masks[i] & omask) {
						++together_count;
					}
				}
				if (together_count >= threshold) {
					flow_groups[oidx] = group_id;
					printk(KERN_ERR "SBD-GROUP assigned group: pi:%i -> %i\n", oidx+1, group_id);
				}
			}
		}
	}
}

// snapshots are already locked by caller
void mptcp_execute_sbd(struct sock* meta_sk, int latest_snapshot_idx) {
    struct tcp_sock *meta_tp = tcp_sk(meta_sk);
    struct mptcp_cb *mpcb = meta_tp->mpcb;
    struct mptcp_tcp_sock *mptcp;
    struct hlist_node *tmp_node;
    struct tcp_sock *tp;

    int i;
    struct sock *sk;
    struct mptcp_flow_stats stats[8];
    int num_subflows, num_congested, next_group_id;
    struct mptcp_sbd_observation *obs;

    printk(KERN_ERR "SBD-BEGIN execute sbd for %p until snapidx %i\n",
        mpcb, latest_snapshot_idx);

    num_subflows = 0;
    mptcp_for_each_sub_safe(mpcb, mptcp, tmp_node) {
        sk = mptcp_to_sock(mptcp);
        tp = tcp_sk(sk);
        if (!tp->mptcp)
            continue;

        // move all subflows forward to latest_snapshot_idx
        mptcp_fill_snapshots_until(tp, latest_snapshot_idx);

        stats[num_subflows].pi = tp->mptcp->path_index;

        process_subflow(&stats[num_subflows], latest_snapshot_idx, tp->mptcp->owd_snapshots);

        // into current statistics incorporate info about previous congestion
        stats[num_subflows].previously_congested = tp->mptcp->previously_congested;
        // and for next time, determine whether flow is congested right now
        tp->mptcp->previously_congested = is_flow_congested(&stats[num_subflows]);

        num_subflows++;
        if (num_subflows >= 8) // do not support more than 8
            break;
    }

    // move congested flows to the front
    num_congested = split_congestion(stats, num_subflows);

    // print info about non-congested/congested flows
    printk(KERN_ERR "SBD-INFO %i not congested:\n", num_subflows - num_congested);
    for (i = num_congested; i < num_subflows; ++i) {
        print_flow_stats(99, &stats[i]);        
    }
    printk(KERN_ERR "SBD-INFO %i congested:\n", num_congested);

    // prepare for storing this observation
    obs = &mpcb->sbd_observations[mpcb->sbd_observations_count];
    memset(obs, 0, sizeof(struct mptcp_sbd_observation));
    mpcb->sbd_observations_count++;

    // save non-congested flows group first
    store_group(obs, stats, num_congested, num_subflows, 1);

    // now split the congested flows into groups
    next_group_id = 1;
    split(obs, stats, 0, num_congested, 0, &next_group_id);

    printk(KERN_ERR "SBD-END execute sbd for %p until snapidx %i: %s (%i)\n",
        mpcb, latest_snapshot_idx, obs->text, obs->len);

    if (mpcb->sbd_observations_count == SBD_MAX_OBSERVATIONS) {
        printk(KERN_ERR "SBD-BEGIN decide for %p\n", mpcb);
        for (i = 0; i < mpcb->sbd_observations_count; ++i) {
          printk(KERN_ERR "%i: %s\n", i+1, mpcb->sbd_observations[i].text);
        }

        // time to merge the observations and decide how to group flows!
        merge_observations(mpcb->groups, mpcb->sbd_observations, mpcb->sbd_observations_count, 5); // if at least 5 times together -> decide: together!
        mpcb->groups_epoch++; // just filled in the next epoch
        if (mpcb->groups_epoch == 0) { // if we wrapped around: 0 actually signals no group data, so don't use that number
            mpcb->groups_epoch = 1;
        }

        mpcb->sbd_observations_count = 0; // consumed them

        printk(KERN_ERR "SBD-END decide for %p: epoch %i\n", mpcb, mpcb->groups_epoch);
    }
}

