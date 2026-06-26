// SPDX-License-Identifier: MIT
/*
 * vpnhide_kmod — kernel module that hides VPN network interfaces from
 * selected Android apps by filtering ioctl, netlink, and procfs
 * responses based on the calling process's UID.
 *
 * Uses kprobes so no modification of the running kernel is needed;
 * works on stock Android GKI kernels with CONFIG_KPROBES=y.
 *
 * Hooks:
 *   - dev_ioctl: filters SIOCGIFFLAGS / SIOCGIFNAME / SIOCGIFMTU / etc.
 *   - sock_ioctl: filters SIOCGIFCONF interface enumeration
 *   - rtnl_fill_ifinfo: filters RTM_NEWLINK netlink dumps (getifaddrs)
 *   - inet6_fill_ifaddr: filters RTM_GETADDR IPv6 responses (getifaddrs)
 *   - inet_fill_ifaddr: filters RTM_GETADDR IPv4 responses (getifaddrs)
 *   - fib_route_seq_show: filters /proc/net/route entries
 *   - ipv6_route_seq_show: filters /proc/net/ipv6_route entries
 *   - fib_dump_info: filters IPv4 RTM_GETROUTE dump replies
 *   - rt6_fill_node: filters IPv6 RTM_GETROUTE replies
 *   - fib_nl_fill_rule: filters policy routing rules for target UIDs
 *
 * Target UIDs are written to /proc/vpnhide_targets from userspace.
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/string.h>
#include <linux/net.h>
#include <linux/if.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>
#include <linux/inetdevice.h>
#include <net/if_inet6.h>
#include <net/ip_fib.h>
#include <net/nexthop.h>
#include <net/ip6_fib.h>
#include <net/ip6_route.h>
#include <net/route.h>
#include <net/fib_rules.h>

#include "generated/iface_lists.h"

#define MODNAME "vpnhide"
#define MAX_TARGET_UIDS 64

/* ------------------------------------------------------------------ */
/*  Debug logging — toggled via /proc/vpnhide_debug                   */
/* ------------------------------------------------------------------ */

static bool debug_enabled;

/*
 * `debug_enabled` is a single bool, written from /proc/vpnhide_debug
 * and read from every probe handler. Use READ_ONCE/WRITE_ONCE so the
 * compiler doesn't tear the access or hoist it across the probe-hot
 * path — kosher kernel style for unsynchronised flags.
 */
#define vpnhide_dbg(fmt, ...)                                     \
	do {                                                      \
		if (READ_ONCE(debug_enabled))                     \
			pr_info(MODNAME ": " fmt, ##__VA_ARGS__); \
	} while (0)

/* ------------------------------------------------------------------ */
/*  VPN interface name matching — see data/interfaces.toml            */
/* ------------------------------------------------------------------ */

#define is_vpn_ifname(name) vpnhide_iface_is_vpn(name)

/* ------------------------------------------------------------------ */
/*  Target UID list                                                   */
/* ------------------------------------------------------------------ */

static uid_t target_uids[MAX_TARGET_UIDS];
static int nr_target_uids;
static DEFINE_SPINLOCK(uids_lock);

static bool is_target_uid(void)
{
	uid_t uid = from_kuid(&init_user_ns, current_uid());
	bool found = false;
	int i;

	spin_lock(&uids_lock);
	for (i = 0; i < nr_target_uids; i++) {
		if (target_uids[i] == uid) {
			found = true;
			break;
		}
	}
	spin_unlock(&uids_lock);
	return found;
}

/* ------------------------------------------------------------------ */
/*  /proc/vpnhide_targets                                             */
/* ------------------------------------------------------------------ */

static ssize_t targets_write(struct file *file, const char __user *ubuf,
			     size_t count, loff_t *ppos)
{
	char *buf, *line, *next;
	int new_count = 0;
	uid_t new_uids[MAX_TARGET_UIDS];

	if (count > PAGE_SIZE)
		return -EINVAL;

	buf = kmalloc(count + 1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	if (copy_from_user(buf, ubuf, count)) {
		kfree(buf);
		return -EFAULT;
	}
	buf[count] = '\0';

	for (line = buf; line && *line && new_count < MAX_TARGET_UIDS;
	     line = next) {
		unsigned long uid;

		next = strchr(line, '\n');
		if (next)
			*next++ = '\0';

		while (*line == ' ' || *line == '\t')
			line++;
		if (!*line || *line == '#')
			continue;

		if (kstrtoul(line, 10, &uid) == 0)
			new_uids[new_count++] = (uid_t)uid;
	}

	spin_lock(&uids_lock);
	memcpy(target_uids, new_uids, new_count * sizeof(uid_t));
	nr_target_uids = new_count;
	spin_unlock(&uids_lock);

	kfree(buf);
	pr_info(MODNAME ": loaded %d target UIDs\n", new_count);
	return count;
}

static int targets_show(struct seq_file *m, void *v)
{
	int i;

	spin_lock(&uids_lock);
	for (i = 0; i < nr_target_uids; i++)
		seq_printf(m, "%u\n", target_uids[i]);
	spin_unlock(&uids_lock);
	return 0;
}

static int targets_open(struct inode *inode, struct file *file)
{
	return single_open(file, targets_show, NULL);
}

static const struct proc_ops targets_proc_ops = {
	.proc_open = targets_open,
	.proc_read = seq_read,
	.proc_write = targets_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

/* ------------------------------------------------------------------ */
/*  /proc/vpnhide_debug                                               */
/* ------------------------------------------------------------------ */

static ssize_t debug_write(struct file *file, const char __user *ubuf,
			   size_t count, loff_t *ppos)
{
	char c;

	if (count == 0)
		return 0;
	if (get_user(c, ubuf))
		return -EFAULT;

	WRITE_ONCE(debug_enabled, c == '1' || c == 'Y' || c == 'y');
	pr_info(MODNAME ": debug %s\n",
		READ_ONCE(debug_enabled) ? "enabled" : "disabled");
	return count;
}

static int debug_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", READ_ONCE(debug_enabled) ? 1 : 0);
	return 0;
}

static int debug_open(struct inode *inode, struct file *file)
{
	return single_open(file, debug_show, NULL);
}

static const struct proc_ops debug_proc_ops = {
	.proc_open = debug_open,
	.proc_read = seq_read,
	.proc_write = debug_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

/* ========================================================================= */
/* ROUTE NETLINK HELPERS                                                     */
/* ========================================================================= */

static bool copy_dev_name(struct net_device *dev, char name[IFNAMSIZ])
{
    if (!dev) return false;
    if (copy_from_kernel_nofault(name, dev->name, IFNAMSIZ) != 0) return false;
    name[IFNAMSIZ - 1] = '\0';
    return true;
}

static bool is_physical_ifname(const char *name)
{
    return vpnhide_iface_starts_with_ci(name, "rmnet") ||
           vpnhide_iface_starts_with_ci(name, "wlan") ||
           vpnhide_iface_starts_with_ci(name, "eth") ||
           vpnhide_iface_starts_with_ci(name, "ccmni") ||
           vpnhide_iface_starts_with_ci(name, "ccemni") ||
           vpnhide_iface_starts_with_ci(name, "seth");
}

static bool is_public_ipv4(__be32 addr)
{
    u32 host = be32_to_cpu(addr);
    u8 a = (host >> 24) & 0xff;
    u8 b = (host >> 16) & 0xff;
    u8 c = (host >> 8) & 0xff;

    if (a == 0 || a == 10 || a == 127 || a >= 224) return false;
    if (a == 100 && b >= 64 && b <= 127) return false;
    if (a == 169 && b == 254) return false;
    if (a == 172 && b >= 16 && b <= 31) return false;
    if (a == 192 && b == 168) return false;
    if (a == 192 && b == 0 && c == 0) return false;
    if (a == 192 && b == 0 && c == 2) return false;
    if (a == 198 && (b == 18 || b == 19)) return false;
    if (a == 198 && b == 51 && c == 100) return false;
    if (a == 203 && b == 0 && c == 113) return false;
    return true;
}

static bool is_public_host_route_via_physical(const struct fib_rt_info *fri, struct net_device *dev)
{
    char name[IFNAMSIZ];
    if (!fri || !dev || fri->dst_len != 32 || !is_public_ipv4(fri->dst)) return false;
    if (!copy_dev_name(dev, name)) return false;
    return is_physical_ifname(name);
}

static bool is_public_ipv6(const struct in6_addr *addr)
{
    u8 b0 = addr->s6_addr[0];
    /* Global unicast 2000::/3 only. Excludes ::/:: 1 (unspec/loopback),
		 * fe80::/10 (link-local), fc00::/7 (ULA), ff00::/8 (multicast). */
    if ((b0 & 0xe0) != 0x20)
			return false;
		/* 2001:db8::/32 documentation range. */
    if (addr->s6_addr[0] == 0x20 && addr->s6_addr[1] == 0x01 &&
        addr->s6_addr[2] == 0x0d && addr->s6_addr[3] == 0xb8)
			return false;
    return true;
}

/* IPv6 analogue of is_public_host_route_via_physical: a /128 route to a
 * public address pinned to a physical interface is the host-route a VPN
 * client installs so tunnel packets can reach the server — it leaks the
 * server's IPv6 even when the tun interface itself is hidden. fib6_dst
 * (struct rt6key { struct in6_addr addr; int plen; }) is stable across
 * GKI 5.10..6.12; read it fault-safe since `rt` comes from a raw reg. */
static bool is_public_host_route6_via_physical(struct fib6_info *rt, struct net_device *dev)
{
    struct in6_addr addr;
    int plen = 0;
    char name[IFNAMSIZ];

    if (!rt || !dev) return false;
    if (copy_from_kernel_nofault(&plen, &rt->fib6_dst.plen, sizeof(plen)) != 0 || plen != 128) return false;
    if (copy_from_kernel_nofault(&addr, &rt->fib6_dst.addr, sizeof(addr)) != 0 || !is_public_ipv6(&addr)) return false;
    if (!copy_dev_name(dev, name)) return false;
    return is_physical_ifname(name);
}

static struct net_device *dev_from_nexthop(struct nexthop *nh)
{
    struct net_device *dev = NULL;
    bool is_group = false;

    if (!nh) return NULL;
    if (copy_from_kernel_nofault(&is_group, &nh->is_group, sizeof(is_group)) != 0) return NULL;

    if (is_group) {
        struct nh_group *nh_grp = NULL;
        struct nexthop *first_nh = NULL;
        u16 num_nh = 0;

        if (copy_from_kernel_nofault(&nh_grp, &nh->nh_grp, sizeof(nh_grp)) != 0 || !nh_grp) return NULL;
        if (copy_from_kernel_nofault(&num_nh, &nh_grp->num_nh, sizeof(num_nh)) != 0 || num_nh == 0) return NULL;
        if (copy_from_kernel_nofault(&first_nh, &nh_grp->nh_entries[0].nh, sizeof(first_nh)) != 0 || !first_nh) return NULL;
        nh = first_nh;
    }

    {
        struct nh_info *nhi = NULL;
        if (copy_from_kernel_nofault(&nhi, &nh->nh_info, sizeof(nhi)) == 0 && nhi) {
            copy_from_kernel_nofault(&dev, &nhi->fib_nhc.nhc_dev, sizeof(dev));
        }
    }
    return dev;
}

static struct net_device *dev_from_fib_info(struct fib_info *fi)
{
    struct net_device *dev = NULL;
    struct nexthop *nh = NULL;

    if (!fi) return NULL;
    if (copy_from_kernel_nofault(&nh, &fi->nh, sizeof(nh)) == 0 && nh) {
        dev = dev_from_nexthop(nh);
    } else {
        int fib_nhs = 0;
        if (copy_from_kernel_nofault(&fib_nhs, &fi->fib_nhs, sizeof(fib_nhs)) == 0 && fib_nhs > 0) {
            copy_from_kernel_nofault(&dev, &fi->fib_nh[0].nh_common.nhc_dev, sizeof(dev));
        }
    }
    return dev;
}

static struct net_device *dev_from_fib6_info(struct fib6_info *rt)
{
    struct net_device *dev = NULL;
    struct nexthop *nh = NULL;

    if (!rt) return NULL;
    if (copy_from_kernel_nofault(&nh, &rt->nh, sizeof(nh)) == 0 && nh) {
        dev = dev_from_nexthop(nh);
    } else {
        copy_from_kernel_nofault(&dev, &rt->fib6_nh[0].nh_common.nhc_dev, sizeof(dev));
    }
    return dev;
}

/* ========================================================================= */
/* HOOK IMPLEMENTATIONS                                                      */
/* ========================================================================= */

/* ================================================================== */
/*  Hook 1: dev_ioctl — all per-interface ioctls                      */
/*                                                                    */
/*  dev_ioctl() on GKI 6.1:                                          */
/*    int dev_ioctl(struct net *net, unsigned int cmd,                */
/*                  struct ifreq *ifr, void __user *data,            */
/*                  bool *need_copyout)                               */
/*  arm64: x0=net, x1=cmd, x2=ifr (KERNEL ptr), x3=data (__user)   */
/*                                                                    */
/*  Covers SIOCGIFFLAGS, SIOCGIFNAME, SIOCGIFMTU, SIOCGIFINDEX,     */
/*  SIOCGIFHWADDR, SIOCGIFADDR, and any other cmd that goes through  */
/*  dev_ioctl with a VPN interface name in ifr_name. Returns ENODEV  */
/*  for all of them.                                                  */
/*                                                                    */
/*  Note: SIOCGIFCONF goes through sock_ioctl -> dev_ifconf, not     */
/*  through dev_ioctl, so it is not covered here.                    */
/* ================================================================== */

typedef int (*dev_ioctl_t)(struct net *net, unsigned int cmd, struct ifreq *ifr, void __user *data, bool *need_copyout);
static dev_ioctl_t orig_dev_ioctl;

static int hook_dev_ioctl(struct net *net, unsigned int cmd, struct ifreq *ifr, void __user *data, bool *need_copyout) {
    int ret = orig_dev_ioctl(net, cmd, ifr, data, need_copyout);

    if (ret == 0 && is_target_uid() && ifr) {
        char name[IFNAMSIZ];
        /* ifr is a kernel pointer here, safe to copy_from_kernel_nofault */
        if (copy_from_kernel_nofault(name, ifr->ifr_name, IFNAMSIZ) == 0) {
            name[IFNAMSIZ - 1] = '\0';
            if (is_vpn_ifname(name)) {
                vpnhide_dbg("dev_ioctl: hiding iface=%s cmd=0x%x\n", name, cmd);
                return -ENODEV;
            }
        }
    }
    return ret;
}

/* ================================================================== */
/*  Hook 2: sock_ioctl — SIOCGIFCONF interface enumeration            */
/*                                                                    */
/*  Why sock_ioctl instead of dev_ifconf?                             */
/*                                                                    */
/*  On GKI 5.10 kernels built with Clang LTO (all stock Android       */
/*  devices), the linker inlines dev_ifconf() into sock_do_ioctl().   */
/*  The symbol "dev_ifconf" stays in kallsyms as a dead stub, so      */
/*  kretprobe registration succeeds but the probe never fires.        */
/*  Confirmed by disassembly on Xiaomi 13 Lite (5.10.136) and Lenovo  */
/*  Legion 2 Pro (5.10.101): no `bl dev_ifconf` in sock_do_ioctl.    */
/*                                                                    */
/*  On 6.1+, SIOCGIFCONF was moved out of sock_do_ioctl() into       */
/*  sock_ioctl() directly (handled in the switch statement), so       */
/*  hooking sock_do_ioctl would miss it on newer kernels.             */
/*                                                                    */
/*  sock_ioctl is the correct hook point because:                     */
/*  1. It is the file_operations->unlocked_ioctl callback for socket  */
/*     fds — used as a function pointer, so LTO cannot inline it.     */
/*  2. ALL socket ioctls, including SIOCGIFCONF, pass through it on   */
/*     every kernel version (5.10 through 6.12+).                     */
/*  3. After sock_ioctl returns, the ifconf data (ifreq array +       */
/*     ifc_len) is already in userspace — we filter it uniformly via  */
/*     copy_from_user/copy_to_user regardless of kernel version.      */
/*                                                                    */
/* ================================================================== */

typedef int (*sock_ioctl_t)(struct file *file, unsigned int cmd, unsigned long arg);
static sock_ioctl_t orig_sock_ioctl;

enum filter_ifconf_result {
    FILTER_IFCONF_NO_CHANGE,
    FILTER_IFCONF_CHANGED,
    FILTER_IFCONF_COPY_FAULT,
};

/* Compact VPN entries out of the userspace ifreq array. The caller is
 * responsible for updating `ifc_len` only on FILTER_IFCONF_CHANGED. */
static enum filter_ifconf_result filter_ifconf_buf(struct ifreq __user *usr_ifr, int n, int *out_len) {
    struct ifreq tmp;
    int i, dst = 0;

    for (i = 0; i < n; i++) {
        if (copy_from_user(&tmp, &usr_ifr[i], sizeof(tmp))) return FILTER_IFCONF_COPY_FAULT;
        tmp.ifr_name[IFNAMSIZ - 1] = '\0';
        if (is_vpn_ifname(tmp.ifr_name)) continue;
        if (dst != i) {
            if (copy_to_user(&usr_ifr[dst], &tmp, sizeof(tmp))) return FILTER_IFCONF_COPY_FAULT;
        }
        dst++;
    }

    if (dst == n) return FILTER_IFCONF_NO_CHANGE;
    *out_len = dst * (int)sizeof(struct ifreq);
    return FILTER_IFCONF_CHANGED;
}

static int hook_sock_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    int ret = orig_sock_ioctl(file, cmd, arg);

    if (ret == 0 && cmd == SIOCGIFCONF && arg && is_target_uid()) {
        struct ifconf __user *uifc = (struct ifconf __user *)arg;
        struct ifconf ifc;
        enum filter_ifconf_result res;

        if (copy_from_user(&ifc, uifc, sizeof(ifc)) == 0 && ifc.ifc_req && ifc.ifc_len > 0) {
            int orig_len = ifc.ifc_len;

            res = filter_ifconf_buf(ifc.ifc_req, ifc.ifc_len / (int)sizeof(struct ifreq), &ifc.ifc_len);

            if (res == FILTER_IFCONF_COPY_FAULT) {
							/*
								* Partial copy failure — buffer may already be
								* half-rewritten. Don't update ifc_len: a shorter
								* length on a partially-compacted buffer hides VPN
								* entries past the truncation but lets earlier ones
								* through, which is worse than just leaving
								* everything visible. Userspace sees the original
								* length and the (mostly-original) buffer.
								*/
                vpnhide_dbg("ifconf: copy fault during filter; ifc_len untouched\n");
            } else if (res == FILTER_IFCONF_CHANGED) {
                if (put_user(ifc.ifc_len, &uifc->ifc_len)) {
                    vpnhide_dbg("ifconf: put_user(ifc_len=%d) failed\n", ifc.ifc_len);
                } else {
                    vpnhide_dbg("sock_ioctl: ifconf filtered %d -> %d bytes\n", orig_len, ifc.ifc_len);
                }
            }
        }
    }
    return ret;
}

/* ================================================================== */
/*  Hook 3: rtnl_fill_ifinfo — netlink RTM_NEWLINK (getifaddrs path)  */
/*                                                                    */
/*  rtnl_fill_ifinfo fills one interface's data into a netlink skb    */
/*  during a RTM_GETLINK dump. If the device is a VPN and the caller  */
/*  is a target UID, we hide the entry from the dump.                 */
/*                                                                    */
/*  We can't return -EMSGSIZE (causes infinite retry of the same      */
/*  entry on android14-6.1, hanging RTM_GETLINK dumps). Instead use   */
/*  the same skb_trim approach as inet6_fill_ifaddr below: save       */
/*  skb->len before the fill, trim back on return, return 0. The      */
/*  iterator then sees a successful entry of zero bytes and advances. */
/*																																		*/
/*  Using a generic 10-argument forwarder to ensure we don't corrupt  */
/*  the stack on x86_64, while correctly intercepting the first       */
/*  2 arguments we need.																							*/
/* ================================================================== */

typedef int (*rtnl_fill_ifinfo_t)(struct sk_buff *skb, struct net_device *dev, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8, void *a9, void *a10);
static rtnl_fill_ifinfo_t orig_rtnl_fill_ifinfo;

static int hook_rtnl_fill_ifinfo(struct sk_buff *skb, struct net_device *dev, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8, void *a9, void *a10) {
    /* Save state BEFORE calling original function using local stack */
    unsigned int saved_len = skb ? skb->len : 0;
    bool target = is_target_uid();
    /* Call the original function transparently */
    int ret = orig_rtnl_fill_ifinfo(skb, dev, a3, a4, a5, a6, a7, a8, a9, a10);

    /* Post-process the result */
    if (ret == 0 && target && skb && dev) {
        rcu_read_lock();
        if (is_vpn_ifname(dev->name)) {
            vpnhide_dbg("rtnl_fill_ifinfo: trimming skb %u -> %u\n", skb->len, saved_len);
            skb_trim(skb, saved_len);
        }
        rcu_read_unlock();
    }
    return ret;
}

/* ================================================================== */
/*  Hook 4: inet6_fill_ifaddr — RTM_GETADDR IPv6 (getifaddrs path)   */
/*                                                                    */
/*  getifaddrs() does RTM_GETLINK (filtered by hook 3) then          */
/*  RTM_GETADDR. Addresses for VPN interfaces still appear in        */
/*  RTM_GETADDR, so bionic reconstructs a tun0 entry with flags=0.  */
/*  Filtering here prevents that.                                    */
/*                                                                    */
/*  We can't return -EMSGSIZE (causes infinite retry on empty skb).  */
/*  Instead, save skb->len before and trim the skb back on return,   */
/*  making it look like the entry was never written. Return 0.       */
/* ================================================================== */

typedef int (*inet6_fill_ifaddr_t)(struct sk_buff *skb, struct inet6_ifaddr *ifa, void *a3);
static inet6_fill_ifaddr_t orig_inet6_fill_ifaddr;

static int hook_inet6_fill_ifaddr(struct sk_buff *skb, struct inet6_ifaddr *ifa, void *a3) {
    /* Save skb length before the fill operation */
    unsigned int saved_len = skb ? skb->len : 0;
    bool target = is_target_uid();
    /* Execute the original function */
    int ret = orig_inet6_fill_ifaddr(skb, ifa, a3);

    /* If it succeeded and target matches, check if we need to trim */
    if (ret == 0 && target && skb && ifa) {
        rcu_read_lock();
        if (ifa->idev && ifa->idev->dev && is_vpn_ifname(ifa->idev->dev->name)) {
            vpnhide_dbg("inet6_fill_ifaddr: trimming skb %u -> %u\n", skb->len, saved_len);
            skb_trim(skb, saved_len);
        }
        rcu_read_unlock();
    }
    return ret;
}

/* ================================================================== */
/*  Hook 5: inet_fill_ifaddr — RTM_GETADDR IPv4 (getifaddrs path)    */
/*  Same skb-trim approach as hook 4.                                */
/* ================================================================== */

typedef int (*inet_fill_ifaddr_t)(struct sk_buff *skb, struct in_ifaddr *ifa, void *a3);
static inet_fill_ifaddr_t orig_inet_fill_ifaddr;

static int hook_inet_fill_ifaddr(struct sk_buff *skb, struct in_ifaddr *ifa, void *a3) {
    /* Save skb length before the fill operation */
    unsigned int saved_len = skb ? skb->len : 0;
    bool target = is_target_uid();
    /* Execute the original function */
    int ret = orig_inet_fill_ifaddr(skb, ifa, a3);

    /* If it succeeded and target matches, check if we need to trim */
    if (ret == 0 && target && skb && ifa) {
        rcu_read_lock();
        if (ifa->ifa_dev && ifa->ifa_dev->dev && is_vpn_ifname(ifa->ifa_dev->dev->name)) {
            vpnhide_dbg("inet_fill_ifaddr: trimming skb %u -> %u\n", skb->len, saved_len);
            skb_trim(skb, saved_len);
        }
        rcu_read_unlock();
    }
    return ret;
}
/* ================================================================== */
/*  Hook 6: fib_route_seq_show — /proc/net/route                      */
/*                                                                    */
/*  fib_route_seq_show(struct seq_file *seq, void *v) writes one or  */
/*  more tab-separated route lines into seq->buf, each ending with   */
/*  '\n'. The first field is the interface name.                      */
/*                                                                    */
/*  We access seq->buf and seq->count without seq_file's internal mutex. */
/*  This is safe because seq_read() drives the ->show() callback      */
/*  synchronously under its own fd context — no concurrent access to  */
/*  the same seq_file is possible because we first call to the original */
/*  function and then our hook is executed.												 	*/
/* ================================================================== */

typedef int (*fib_route_seq_show_t)(struct seq_file *seq, void *v);
static fib_route_seq_show_t orig_fib_route_seq_show;

static int hook_fib_route_seq_show(struct seq_file *seq, void *v) {
    size_t start_count = seq ? seq->count : 0;
    int ret = orig_fib_route_seq_show(seq, v);

    if (ret == 0 && is_target_uid() && seq && seq->buf && seq->count > start_count) {
				/*
				* Scan the region [start_count, seq->count) for lines whose
				* first tab-separated field is a VPN interface name. Compact
				* out matching lines in place and adjust seq->count.
				*
				* Each route line looks like: "tun0\t08000000\t...\n"
				*/
        char *buf = seq->buf;
        char *src = buf + start_count;
        char *dst = src;
        char *end = buf + seq->count;
        char ifname[IFNAMSIZ];
        int j;

        while (src < end) {
            char *nl = memchr(src, '\n', end - src);
            char *line_end = nl ? nl + 1 : end;
            size_t line_len = line_end - src;

						/* Extract the interface name (first field, tab-delimited) */
            for (j = 0; j < IFNAMSIZ - 1 && j < (int)line_len && src[j] != '\t' && src[j] != '\n'; j++)
                ifname[j] = src[j];
            ifname[j] = '\0';

            if (is_vpn_ifname(ifname)) {
								/* Skip this line */
                src = line_end;
                continue;
            }

						/* Keep this line — move it down if there's a gap */
            if (dst != src)
							memmove(dst, src, line_len);
            dst += line_len;
            src = line_end;
        }
        seq->count = dst - buf;
    }
    return ret;
}

/* ================================================================== */
/*  Hook 7: ipv6_route_seq_show — /proc/net/ipv6_route                */
/*                                                                    */
/*  IPv6 route lines store the interface name in the final field.     */
/*  We compact VPN lines out of the seq_file buffer, matching the     */
/*  IPv4 /proc/net/route strategy above.                              */
/* ================================================================== */

typedef int (*ipv6_route_seq_show_t)(struct seq_file *seq, void *v);
static ipv6_route_seq_show_t orig_ipv6_route_seq_show;

static int hook_ipv6_route_seq_show(struct seq_file *seq, void *v) {
    size_t start_count = seq ? seq->count : 0;
    int ret = orig_ipv6_route_seq_show(seq, v);

    if (ret == 0 && is_target_uid() && seq && seq->buf && seq->count > start_count) {
        char *buf = seq->buf;
        char *src = buf + start_count;
        char *dst = src;
        char *end = buf + seq->count;
        char ifname[IFNAMSIZ];
        int j;

        while (src < end) {
            char *nl = memchr(src, '\n', end - src);
            char *line_end = nl ? nl + 1 : end;
            size_t line_len = line_end - src;
            char *field_start;
            char *field_end = line_end;

            /* Parse backwards from the end of the line to find the last field */
            while (field_end > src &&
                   (field_end[-1] == '\n' || field_end[-1] == '\r' ||
                    field_end[-1] == ' ' || field_end[-1] == '\t'))
                field_end--;
            
            field_start = field_end;
            while (field_start > src && field_start[-1] != ' ' &&
                   field_start[-1] != '\t')
                field_start--;

            /* Copy the extracted interface name */
            for (j = 0; j < IFNAMSIZ - 1 && (field_start + j) < field_end; j++)
                ifname[j] = field_start[j];
            ifname[j] = '\0';

            /* If it matches a VPN interface, skip this line in the buffer */
            if (is_vpn_ifname(ifname)) {
                vpnhide_dbg("ipv6_route_seq_show: hiding route for %s\n", ifname);
                src = line_end;
                continue;
            }

            /* Otherwise, shift the line back into the valid portion of the buffer */
            if (dst != src)
                memmove(dst, src, line_len);
            dst += line_len;
            src = line_end;
        }
        seq->count = dst - buf;
    }
    return ret;
}

/* ================================================================== */
/*  Hook 8: fib_dump_info — IPv4 RTM_GETROUTE dumps                   */
/* ================================================================== */

typedef int (*fib_dump_info_t)(struct sk_buff *skb, void *a2, void *a3, void *a4, struct fib_rt_info *fri, void *a6);
static fib_dump_info_t orig_fib_dump_info;

static int hook_fib_dump_info(struct sk_buff *skb, void *a2, void *a3, void *a4, struct fib_rt_info *fri, void *a6) {
    unsigned int saved_len = skb ? skb->len : 0;
    bool target = is_target_uid();
    int ret = orig_fib_dump_info(skb, a2, a3, a4, fri, a6);

    if (ret >= 0 && target && skb && fri) {
        struct fib_rt_info fri_copy;
        if (copy_from_kernel_nofault(&fri_copy, fri, sizeof(fri_copy)) == 0) {
            struct net_device *dev;
            char dev_name[IFNAMSIZ];
            bool vpn_route, host_hint;

            rcu_read_lock();
            dev = dev_from_fib_info(fri_copy.fi);
            if (copy_dev_name(dev, dev_name)) {
                vpn_route = is_vpn_ifname(dev_name);
                host_hint = is_public_host_route_via_physical(&fri_copy, dev);
                if (vpn_route || host_hint) {
                    vpnhide_dbg("fib_dump_info: hiding %s via %s\n", vpn_route ? "VPN route" : "public host route", dev_name);
                    skb_trim(skb, saved_len);
                    ret = 0; /* Report success despite trimming, to keep netlink iteration going */
                }
            }
            rcu_read_unlock();
        }
    }
    return ret;
}

/* ================================================================== */
/*  Hook 9: rt6_fill_node — IPv6 RTM_GETROUTE                         */
/* ================================================================== */

typedef int (*rt6_fill_node_t)(void *net, struct sk_buff *skb, struct fib6_info *rt, struct dst_entry *dst, void *a5, void *a6, void *a7, void *a8, void *a9, void *a10);
static rt6_fill_node_t orig_rt6_fill_node;

static int hook_rt6_fill_node(void *net, struct sk_buff *skb, struct fib6_info *rt, struct dst_entry *dst, void *a5, void *a6, void *a7, void *a8, void *a9, void *a10) {
    unsigned int saved_len = skb ? skb->len : 0;
    bool target = is_target_uid();
    int ret = orig_rt6_fill_node(net, skb, rt, dst, a5, a6, a7, a8, a9, a10);

    if (ret >= 0 && target && skb) {
        struct net_device *dev = NULL;
        char dev_name[IFNAMSIZ];
        
        rcu_read_lock();
        dev = dev_from_fib6_info(rt);
        if (!dev && dst) copy_from_kernel_nofault(&dev, &dst->dev, sizeof(dev));
        
        if (copy_dev_name(dev, dev_name)) {
            bool vpn_route = is_vpn_ifname(dev_name);
            bool host_hint = !vpn_route && is_public_host_route6_via_physical(rt, dev);

            if (vpn_route || host_hint) {
                vpnhide_dbg("rt6_fill_node: hiding %s via %s\n", vpn_route ? "VPN route" : "public host route", dev_name);
                skb_trim(skb, saved_len);
                ret = 0; /* Report success despite trimming */
            }
        }
        rcu_read_unlock();
    }
    return ret;
}

/*
 * Note: rt_fill_info (single-lookup RTM_GETROUTE serializer for
 * `ip route get <dst>`) is intentionally NOT hooked.
 *
 * It is a `static` function called directly within net/ipv4/route.c, so
 * the compiler is free to ignore AAPCS64 and assign its arguments to
 * arbitrary registers (interprocedural register allocation). Verified in
 * QEMU on a no-LTO android12-5.10 build: regs[3] held table_id (254),
 * not the `struct rtable *` the source signature places there — so no
 * fixed regs[N] read is correct across builds (the value differs between
 * LTO device builds and no-LTO builds). A hardcoded register is build-
 * dependent guesswork that fails silently (or panics, without nofault).
 *
 * It is also low value here: IPv4 route *enumeration* (RTM_GETROUTE with
 * NLM_F_DUMP — what detection apps actually use) goes through the global,
 * ABI-stable fib_dump_info hook above, not rt_fill_info. Single lookups
 * respect the caller's own routing, which under the recommended split-
 * tunnel setup resolves to the physical interface anyway.
 *
 * If single-lookup concealment is ever needed, hook rtnl_unicast instead
 * (global EXPORT_SYMBOL, ABI-stable, runs in caller context) and rewrite
 * RTA_OIF in the reply skb — see docs/ROADMAP.md.
 */

/* ================================================================== */
/*  Hook 10: fib_nl_fill_rule — RTM_GETRULE policy rules              */
/* ================================================================== */
typedef int (*fib_nl_fill_rule_t)(struct sk_buff *skb, struct fib_rule *rule, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8, void *a9, void *a10);
static fib_nl_fill_rule_t orig_fib_nl_fill_rule;

static int hook_fib_nl_fill_rule(struct sk_buff *skb, struct fib_rule *rule, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8, void *a9, void *a10) {
    unsigned int saved_len = skb ? skb->len : 0;
    bool target = is_target_uid();
    int ret = orig_fib_nl_fill_rule(skb, rule, a3, a4, a5, a6, a7, a8, a9, a10);

    if (ret >= 0 && target && skb && rule) {
        struct fib_rule rule_copy;
        
        if (copy_from_kernel_nofault(&rule_copy, rule, sizeof(rule_copy)) == 0) {
            uid_t uid = from_kuid(&init_user_ns, current_uid());
            bool filter = false;

            if ((rule_copy.iifname[0] != '\0' && is_vpn_ifname(rule_copy.iifname)) ||
                (rule_copy.oifname[0] != '\0' && is_vpn_ifname(rule_copy.oifname))) {
                filter = true;
            } else {
                uid_t start = from_kuid(&init_user_ns, rule_copy.uid_range.start);
                uid_t end = from_kuid(&init_user_ns, rule_copy.uid_range.end);

                if (uid >= start && uid <= end && (start != 0 || end != (uid_t)~0) &&
                    rule_copy.table != RT_TABLE_MAIN && rule_copy.table != RT_TABLE_LOCAL &&
                    rule_copy.table != RT_TABLE_DEFAULT && rule_copy.table > 100) {
                    filter = true;
                }
            }

            if (filter) {
                vpnhide_dbg("fib_nl_fill_rule: hiding policy rule table=%u\n", rule_copy.table);
                skb_trim(skb, saved_len);
                ret = 0; /* Report success despite trimming */
            }
        }
    }
    return ret;
}

/* ========================================================================= */
/* MODULE INITIALIZATION                                                     */
/* ========================================================================= */

/*** Kprobes Engine ***/

#ifdef __x86_64__
    #define PT_REGS_IP(regs) ((regs)->ip)
    #define MCOUNT_INSN_SIZE 5
#else
    #define PT_REGS_IP(regs) ((regs)->pc)
#endif

struct kprobe_hook {
    const char *name;
    void *hook_fn;
    void *orig_fn;
    struct kprobe kp;
    bool registered;
};

static struct kprobe_hook hooks[] = {
    { .name = "dev_ioctl",           .hook_fn = hook_dev_ioctl,           .orig_fn = &orig_dev_ioctl },
    { .name = "sock_ioctl",          .hook_fn = hook_sock_ioctl,          .orig_fn = &orig_sock_ioctl },
    { .name = "rtnl_fill_ifinfo",    .hook_fn = hook_rtnl_fill_ifinfo,    .orig_fn = &orig_rtnl_fill_ifinfo },
    { .name = "inet6_fill_ifaddr",   .hook_fn = hook_inet6_fill_ifaddr,   .orig_fn = &orig_inet6_fill_ifaddr },
    { .name = "inet_fill_ifaddr",    .hook_fn = hook_inet_fill_ifaddr,    .orig_fn = &orig_inet_fill_ifaddr },
    { .name = "fib_route_seq_show",  .hook_fn = hook_fib_route_seq_show,  .orig_fn = &orig_fib_route_seq_show },
    { .name = "ipv6_route_seq_show", .hook_fn = hook_ipv6_route_seq_show, .orig_fn = &orig_ipv6_route_seq_show },
    { .name = "fib_dump_info",       .hook_fn = hook_fib_dump_info,       .orig_fn = &orig_fib_dump_info },
    { .name = "rt6_fill_node",       .hook_fn = hook_rt6_fill_node,       .orig_fn = &orig_rt6_fill_node },
    { .name = "fib_nl_fill_rule",    .hook_fn = hook_fib_nl_fill_rule,    .orig_fn = &orig_fib_nl_fill_rule },
};

static int notrace kprobe_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct kprobe_hook *hook = container_of(p, struct kprobe_hook, kp);

#if defined(__aarch64__)
    if (p->ainsn.api.insn) *((unsigned long*) hook->orig_fn) = (unsigned long)p->ainsn.api.insn;
    else *((unsigned long*) hook->orig_fn) = (unsigned long)p->addr + MCOUNT_INSN_SIZE;
#else
    if (p->ainsn.insn) *((unsigned long*) hook->orig_fn) = (unsigned long)p->ainsn.insn;
    else *((unsigned long*) hook->orig_fn) = (unsigned long)p->addr + MCOUNT_INSN_SIZE;
#endif

    PT_REGS_IP(regs) = (unsigned long)hook->hook_fn;
    return 1;
}
NOKPROBE_SYMBOL(kprobe_pre_handler);

static int register_kprobe_hook(struct kprobe_hook *hook) {
    int ret;
    memset(&hook->kp, 0, sizeof(struct kprobe));
    hook->kp.symbol_name = hook->name;
    hook->kp.pre_handler = kprobe_pre_handler;
    ret = register_kprobe(&hook->kp);
    if (ret == 0) hook->registered = true;
    return ret;
}

static void unregister_kprobe_hook(struct kprobe_hook *hook) {
    if (hook->registered) {
        unregister_kprobe(&hook->kp);
        hook->registered = false;
    }
}

static struct proc_dir_entry *targets_entry;
static struct proc_dir_entry *debug_entry;

static int __init vpnhide_init(void) {
    int i, ret, ok = 0;

    for (i = 0; i < ARRAY_SIZE(hooks); i++) {
        ret = register_kprobe_hook(&hooks[i]);
        if (ret == 0) ok++;
        else pr_warn(MODNAME ": hook(%s) failed: %d\n", hooks[i].name, ret);
    }

    if (ok == 0) {
        pr_err(MODNAME ": no hooks registered, aborting\n");
        return -ENOENT;
    }

    /* 0600: root-only read/write. Apps must not see the target list. */
    targets_entry = proc_create("vpnhide_targets", 0600, NULL, &targets_proc_ops);
    if (!targets_entry) {
        pr_err(MODNAME ": proc_create(vpnhide_targets) failed; aborting\n");
        for (i = 0; i < ARRAY_SIZE(hooks); i++) {
						unregister_kprobe_hook(&hooks[i]);
				}
        return -ENOMEM;
    }

    debug_entry = proc_create("vpnhide_debug", 0600, NULL, &debug_proc_ops);
    if (!debug_entry) {
        pr_warn(MODNAME ": proc_create(vpnhide_debug) failed; debug toggle unavailable\n");
    }

    pr_info(MODNAME ": loaded - write UIDs to /proc/vpnhide_targets\n");
    return 0;
}

static void __exit vpnhide_exit(void) {
    int i;

    if (debug_entry) proc_remove(debug_entry);
    if (targets_entry) proc_remove(targets_entry);

    for (i = 0; i < ARRAY_SIZE(hooks); i++) {
        unregister_kprobe_hook(&hooks[i]);
    }
    pr_info(MODNAME ": unloaded\n");
}

module_init(vpnhide_init);
module_exit(vpnhide_exit);

/* The source is MIT-licensed (see SPDX header), but MODULE_LICENSE("GPL")
 * is required to resolve EXPORT_SYMBOL_GPL symbols (kretprobes, etc.)
 * at module load time. */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("okhsunrog, maxsteeel");
MODULE_DESCRIPTION("Hide VPN interfaces from selected apps at kernel level");
