/*
 * MPTCP implementation - OPPORTUNISTIC LINKED INCREASES CONGESTION CONTROL:
 *
 * Algorithm design:
 * Ramin Khalili <ramin.khalili@epfl.ch>
 * Nicolas Gast <nicolas.gast@epfl.ch>
 * Jean-Yves Le Boudec <jean-yves.leboudec@epfl.ch>
 *
 * Implementation:
 * Ramin Khalili <ramin.khalili@epfl.ch>
 *
 * Ported to the official MPTCP-kernel:
 * Christoph Paasch <christoph.paasch@uclouvain.be>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */


#include <net/tcp.h>
#include <net/mptcp.h>

#include <linux/module.h>

static unsigned char debug_mode __read_mostly = 0;
module_param(debug_mode, byte, 0644);
MODULE_PARM_DESC(debug_mode, "If not 0, will print information via printk(KERN_ERR).");

static int scale = 10;

struct mptcp_olia {
	u32	mptcp_loss1;
	u32	mptcp_loss2;
	u32	mptcp_loss3;
	int	epsilon_num;
	u32	epsilon_den;
	int	mptcp_snd_cwnd_cnt;
};

static u16 mptcp_olia_get_latest_epoch(struct mptcp_cb *mpcb)
{
	u16 latest_epoch = 0; /* invalid epoch */

	struct sock *sk_it;
	struct mptcp_tcp_sock *mptcp;
	struct tcp_sock *tp_it;

	mptcp_for_each_sub(mpcb, mptcp) {
		sk_it = mptcp_to_sock(mptcp);
		tp_it = tcp_sk(sk_it);
		int idx;
		u16 epoch;

		if (!mptcp_sk_can_send(sk_it))
			continue;
		if (!tcp_sk(sk_it)->srtt_us)
			continue;

		idx = (tp_it->mptcp->group_history_next - 1 + MPTCP_GROUP_HISTORY_SIZE) % MPTCP_GROUP_HISTORY_SIZE; /* index of latest item */
		epoch = tp_it->mptcp->group_history[idx].epoch;
		if (epoch > latest_epoch)
			latest_epoch = epoch;
	}

	return latest_epoch;
}

// -1 if no data available
// non-negative number: group
static int mptcp_olia_get_subflow_group_nofilter99(u16 epoch, struct sock *sk)
{
	int i, group = -1;
	struct tcp_sock *tp = tcp_sk(sk);

	if (epoch == 0)
		return -1; // invalid epoch, definitely no group

	if (!mptcp_sk_can_send(sk))
		return -1;
	if (!tcp_sk(sk)->srtt_us)
		return -1;

	for (i = 0; i < MPTCP_GROUP_HISTORY_SIZE; i++) {
		if (debug_mode > 1) printk(KERN_ERR "flow %i, idx %i, epoch %i, group %i\n", tcp_sk(sk)->mptcp->path_index, i, tp->mptcp->group_history[i].epoch, tp->mptcp->group_history[i].group);
		if (tp->mptcp->group_history[i].epoch == epoch) {
			group = tp->mptcp->group_history[i].group;
			break;
		}
	}

	return group;
}

static int mptcp_olia_get_subflow_group(u16 epoch, struct sock *sk)
{
  int group = mptcp_olia_get_subflow_group_nofilter99(epoch, sk);
  // -1 means we have no information at all about a flow
  // 99 means a flow is not congested, then we also have no grouping information
  if (group == 99)
    group = -1;
  return group;
}

static int mptcp_olia_subflow_has_group_epochs(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int idx;
	u16 epoch;

	if (!mptcp_sk_can_send(sk))
		return 0;
	if (!tcp_sk(sk)->srtt_us)
		return 0;

	idx = (tp->mptcp->group_history_next - 1 + MPTCP_GROUP_HISTORY_SIZE) % MPTCP_GROUP_HISTORY_SIZE; /* index of latest item */
	epoch = tp->mptcp->group_history[idx].epoch;
	return (epoch > 0); // last received epoch is valid
}

static u16 mptcp_olia_get_epoch(struct mptcp_cb *mpcb)
{
	int i;
	int all_have_epoch;

	u16 latest_epoch = mptcp_olia_get_latest_epoch(mpcb);
	if (latest_epoch == 0) {
		if (debug_mode > 1) printk(KERN_ERR "do not have any epoch yet!\n");
		return 0; // don't have any epoch
	}

	// look at all subflows: return the epoch that all subflows have
	// (exception: subflows that don't have any epoch data yet are ignored - they just appeared)
	for (i = 0; i < MPTCP_GROUP_HISTORY_SIZE; i++) {
		struct sock *sk_it;
		struct mptcp_tcp_sock *mptcp;
		int group;

		u16 search_epoch = latest_epoch - i;
		if (search_epoch == 0)
			break; // done here

		all_have_epoch = 1; // start with the assumpation that all have data for this epoch
		mptcp_for_each_sub(mpcb, mptcp) {
			sk_it = mptcp_to_sock(mptcp);
			if (!mptcp_olia_subflow_has_group_epochs(sk_it)) {
				if (debug_mode > 1) printk(KERN_ERR "skipping flow %i, no group data at all\n", tcp_sk(sk_it)->mptcp->path_index);
				continue; // if this subflow has no group data at all, ignore it
			}

			group = mptcp_olia_get_subflow_group_nofilter99(search_epoch, sk_it); // do not translate 99 to -1 or check below will be wrong!
			if (group == -1) {
				if (debug_mode > 1) printk(KERN_ERR "skipping flow %i, no group data in epoch %i\n", tcp_sk(sk_it)->mptcp->path_index, search_epoch);
				all_have_epoch = 0; // this one doesn't have data in the epoch
				break;
			}
		}

		if (all_have_epoch)
			return search_epoch;
	}

	if (debug_mode > 1) printk(KERN_ERR "couldn't find shared epoch!\n");
	return 0; // invalid epoch
}

static int mptcp_olia_sk_can_send(struct sock *sk, u16 epoch, int group)
{
	int sk_group;

	if (!mptcp_sk_can_send(sk))
		return 0;

	if (!tcp_sk(sk)->srtt_us)
		return 0;

	// in case we are doing CA for a non-congested flow:
	// consider all flows regardless of their group for coupling
	if (group == -1)
		return 1;

	// if we are doing CA for a flow that is in a group:
	// do not consider flows from other groups, but DO CONSIDER
	// non-congested (-1/99) flows because they might appear
	// in the group at any moment and we want to be careful
	sk_group = mptcp_olia_get_subflow_group(epoch, sk);
	if (sk_group == -1)
		return 1; // other is non-congested
	else if (sk_group == group)
		return 1; // same group
	else
		return 0; // different group
}

static inline u64 mptcp_olia_scale(u64 val, int scale)
{
	return (u64) val << scale;
}

/* take care of artificially inflate (see RFC5681)
 * of cwnd during fast-retransmit phase
 */
static u32 mptcp_get_crt_cwnd(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_ca_state == TCP_CA_Recovery)
		return tcp_sk(sk)->snd_ssthresh;
	else
		return tcp_sk(sk)->snd_cwnd;
}

/* return the dominator of the first term of  the increasing term */
static u64 mptcp_get_rate(struct mptcp_cb *mpcb , u32 path_rtt, u16 epoch, int group)
{
	struct sock *sk;
	struct mptcp_tcp_sock *mptcp;
	struct tcp_sock *tp;
	u64 rate = 1; /* We have to avoid a zero-rate because it is used as a divisor */

	mptcp_for_each_sub(mpcb, mptcp) {
		sk = mptcp_to_sock(mptcp);
		tp = tcp_sk(sk);
		u64 scaled_num;
		u32 tmp_cwnd;

		if (!mptcp_olia_sk_can_send(sk, epoch, group))
			continue;

		tmp_cwnd = mptcp_get_crt_cwnd(sk);
		scaled_num = mptcp_olia_scale(tmp_cwnd, scale) * path_rtt;
		rate += div_u64(scaled_num , tp->srtt_us);
	}
	rate *= rate;
	return rate;
}

/* find the maximum cwnd, used to find set M */
static u32 mptcp_get_max_cwnd(struct mptcp_cb *mpcb, u16 epoch, int group)
{
	struct sock *sk;
	struct mptcp_tcp_sock *mptcp;
	u32 best_cwnd = 0;

	mptcp_for_each_sub(mpcb, mptcp) {
		sk = mptcp_to_sock(mptcp);
		u32 tmp_cwnd;

		if (!mptcp_olia_sk_can_send(sk, epoch, group))
			continue;

		tmp_cwnd = mptcp_get_crt_cwnd(sk);
		if (tmp_cwnd > best_cwnd)
			best_cwnd = tmp_cwnd;
	}
	return best_cwnd;
}

static void mptcp_get_epsilon(struct mptcp_cb *mpcb, u16 epoch, int group)
{
	struct mptcp_olia *ca;
	struct tcp_sock *tp;
	struct sock *sk;
	struct mptcp_tcp_sock *mptcp;
	u64 tmp_int, tmp_rtt, best_int = 0, best_rtt = 1;
	u32 max_cwnd = 1, best_cwnd = 1, tmp_cwnd;
	u8 M = 0, B_not_M = 0;
	int group_cnt = 0;

	/* TODO - integrate this in the following loop - we just want to iterate once */

	max_cwnd = mptcp_get_max_cwnd(mpcb, epoch, group);

	/* find the best path */
	mptcp_for_each_sub(mpcb, mptcp) {
		sk = mptcp_to_sock(mptcp);
		tp = tcp_sk(sk);
		ca = inet_csk_ca(sk);

		if (!mptcp_olia_sk_can_send(sk, epoch, group))
			continue;

		// count the flow
		group_cnt++;

		tmp_rtt = (u64)tp->srtt_us * tp->srtt_us;
		/* TODO - check here and rename variables */
		tmp_int = max(ca->mptcp_loss3 - ca->mptcp_loss2,
			      ca->mptcp_loss2 - ca->mptcp_loss1);

		tmp_cwnd = mptcp_get_crt_cwnd(sk);
		if ((u64)tmp_int * best_rtt >= (u64)best_int * tmp_rtt) {
			best_rtt = tmp_rtt;
			best_int = tmp_int;
			best_cwnd = tmp_cwnd;
		}
	}

	/* TODO - integrate this here in mptcp_get_max_cwnd and in the previous loop */
	/* find the size of M and B_not_M */
	mptcp_for_each_sub(mpcb, mptcp) {
		sk = mptcp_to_sock(mptcp);
		tp = tcp_sk(sk);
		ca = inet_csk_ca(sk);

		if (!mptcp_olia_sk_can_send(sk, epoch, group))
			continue;

		tmp_cwnd = mptcp_get_crt_cwnd(sk);
		if (tmp_cwnd == max_cwnd) {
			M++;
		} else {
			tmp_rtt = (u64)tp->srtt_us * tp->srtt_us;
			tmp_int = max(ca->mptcp_loss3 - ca->mptcp_loss2,
				      ca->mptcp_loss2 - ca->mptcp_loss1);

			if ((u64)tmp_int * best_rtt == (u64)best_int * tmp_rtt)
				B_not_M++;
		}
	}

	/* check if the path is in M or B_not_M and set the value of epsilon accordingly */
	mptcp_for_each_sub(mpcb, mptcp) {
		sk = mptcp_to_sock(mptcp);
		tp = tcp_sk(sk);
		ca = inet_csk_ca(sk);

		if (!mptcp_olia_sk_can_send(sk, epoch, group))
			continue;

		if (B_not_M == 0) {
			ca->epsilon_num = 0;
			ca->epsilon_den = 1;
		} else {
			tmp_rtt = (u64)tp->srtt_us * tp->srtt_us;
			tmp_int = max(ca->mptcp_loss3 - ca->mptcp_loss2,
				      ca->mptcp_loss2 - ca->mptcp_loss1);
			tmp_cwnd = mptcp_get_crt_cwnd(sk);

			if (tmp_cwnd < max_cwnd &&
			    (u64)tmp_int * best_rtt == (u64)best_int * tmp_rtt) {
				ca->epsilon_num = 1;
				ca->epsilon_den = group_cnt * B_not_M;
			} else if (tmp_cwnd == max_cwnd) {
				ca->epsilon_num = -1;
				ca->epsilon_den = group_cnt * M;
			} else {
				ca->epsilon_num = 0;
				ca->epsilon_den = 1;
			}
		}
	}
}

/* setting the initial values */
static void mptcp_olia_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_olia *ca = inet_csk_ca(sk);

	if (mptcp(tp)) {
		ca->mptcp_loss1 = tp->snd_una;
		ca->mptcp_loss2 = tp->snd_una;
		ca->mptcp_loss3 = tp->snd_una;
		ca->mptcp_snd_cwnd_cnt = 0;
		ca->epsilon_num = 0;
		ca->epsilon_den = 1;
	}
}

/* updating inter-loss distance and ssthresh */
static void mptcp_olia_set_state(struct sock *sk, u8 new_state)
{
	if (!mptcp(tcp_sk(sk)))
		return;

	if (new_state == TCP_CA_Loss ||
	    new_state == TCP_CA_Recovery || new_state == TCP_CA_CWR) {
		struct mptcp_olia *ca = inet_csk_ca(sk);

		if (ca->mptcp_loss3 != ca->mptcp_loss2 &&
		    !inet_csk(sk)->icsk_retransmits) {
			ca->mptcp_loss1 = ca->mptcp_loss2;
			ca->mptcp_loss2 = ca->mptcp_loss3;
		}
	}
}

/* group == -1:
   OLIA for subflows that do not have grouping
   When a subflow has no grouping yet, we calculate OLIA increase by considering all subflows
   not just the ones in its group (it does not have a group!)
   group >= 0:
   OLIA for subflows that do have grouping
   When a subflow has grouping, we calculate OLIA increase by considering all subflows in the group
   and all flows without a group - we want to couple against them, too, because they
   could appear in the group in any moment!
*/
static void mptcp_olia_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_olia *ca = inet_csk_ca(sk);
	struct mptcp_cb *mpcb = tp->mpcb;
	struct sock *sk_it;
	struct mptcp_tcp_sock *mptcp_sk;

	u16 epoch;
	int group, group_cnt;

	u64 inc_num, inc_den, rate, cwnd_scaled;

	if (!mptcp(tp)) {
		tcp_reno_cong_avoid(sk, ack, acked);
		return;
	}

	ca->mptcp_loss3 = tp->snd_una;

	if (!tcp_is_cwnd_limited(sk))
		return;

	/* slow start if it is in the safe area */
	if (tp->snd_cwnd <= tp->snd_ssthresh) {
		tcp_slow_start(tp, acked);
		return;
	}

	epoch = mptcp_olia_get_epoch(mpcb);
	group = mptcp_olia_get_subflow_group(epoch, sk);

	// count the flows and determine whether we can simply do reno!
	group_cnt = 0;
	mptcp_for_each_sub(mpcb, mptcp_sk) {
		sk_it = mptcp_to_sock(mptcp_sk);
		if (!mptcp_olia_sk_can_send(sk_it, epoch, group))
			continue;
		group_cnt++;
	}
	if (group_cnt == 1) {
		if (debug_mode) printk(KERN_ERR "RENO pi %i: epoch %i group %i\n", tp->mptcp->path_index, epoch, group);
		// alone in the group means we do reno!
		tcp_reno_cong_avoid(sk, ack, acked);
		return;
	}

	if (debug_mode) printk(KERN_ERR "OLIA(%i) pi %i: epoch %i group %i\n", group_cnt, tp->mptcp->path_index, epoch, group);

	mptcp_get_epsilon(mpcb, epoch, group);
	rate = mptcp_get_rate(mpcb, tp->srtt_us, epoch, group);
	cwnd_scaled = mptcp_olia_scale(tp->snd_cwnd, scale);
	inc_den = ca->epsilon_den * tp->snd_cwnd * rate ? : 1;

	/* calculate the increasing term, scaling is used to reduce the rounding effect */
	if (ca->epsilon_num == -1) {
		if (ca->epsilon_den * cwnd_scaled * cwnd_scaled < rate) {
			inc_num = rate - ca->epsilon_den *
				cwnd_scaled * cwnd_scaled;
			ca->mptcp_snd_cwnd_cnt -= div64_u64(
			    mptcp_olia_scale(inc_num , scale) , inc_den);
		} else {
			inc_num = ca->epsilon_den *
			    cwnd_scaled * cwnd_scaled - rate;
			ca->mptcp_snd_cwnd_cnt += div64_u64(
			    mptcp_olia_scale(inc_num , scale) , inc_den);
		}
	} else {
		inc_num = ca->epsilon_num * rate +
		    ca->epsilon_den * cwnd_scaled * cwnd_scaled;
		ca->mptcp_snd_cwnd_cnt += div64_u64(
		    mptcp_olia_scale(inc_num , scale) , inc_den);
	}


	if (ca->mptcp_snd_cwnd_cnt >= (1 << scale) - 1) {
		if (tp->snd_cwnd < tp->snd_cwnd_clamp)
			tp->snd_cwnd++;
		ca->mptcp_snd_cwnd_cnt = 0;
	} else if (ca->mptcp_snd_cwnd_cnt <= 0 - (1 << scale) + 1) {
		tp->snd_cwnd = max((int) 1 , (int) tp->snd_cwnd - 1);
		ca->mptcp_snd_cwnd_cnt = 0;
	}
}

static u32 mptcp_olia_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	if (unlikely(!mptcp(tp)))
		return tcp_reno_ssthresh(sk);
    else // TODO if it is alone in its group, should it behave like reno?
		return max(tp->snd_cwnd >> 1U, 1U); // let it go down to 1
}

// identical to tcp_reno_min_cwnd but can deal with ssthresh=1
// (and then doesn't let CWND go below 1)
/* static u32 mptcp_olia_min_cwnd(const struct sock *sk)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    return max(tp->snd_ssthresh/2, 1U);
} */

static struct tcp_congestion_ops mptcp_oliasbdx = {
	.init		= mptcp_olia_init,
	.ssthresh	= mptcp_olia_ssthresh,
	.cong_avoid	= mptcp_olia_cong_avoid,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.set_state	= mptcp_olia_set_state,
	.owner		= THIS_MODULE,
	.name		= "oliasbdx",
};

static int __init mptcp_olia_register(void)
{
	BUILD_BUG_ON(sizeof(struct mptcp_olia) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&mptcp_oliasbdx);
}

static void __exit mptcp_olia_unregister(void)
{
	tcp_unregister_congestion_control(&mptcp_oliasbdx);
}

module_init(mptcp_olia_register);
module_exit(mptcp_olia_unregister);

MODULE_AUTHOR("Ramin Khalili, Nicolas Gast, Jean-Yves Le Boudec, Simone Ferlin");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MPTCP COUPLED CONGESTION CONTROL FOR SBD");
MODULE_VERSION("0.1");
