// SPDX-License-Identifier: GPL-2.0-only
/*
 * BOSC Nanhu IRQ preemption test driver
 *
 * This driver is intentionally tiny: it binds to selected non-secure irqgen
 * nodes and services their REE/Linux handlers.
 *
 * For IRQ42 it also triggers secure IRQ43 from inside the IRQ42 hardirq
 * handler. The expected log order is:
 *
 *   [ree] irq42 begin
 *   plic-sec/... -> OP-TEE secure IRQ43 path
 *   [ree] irq42 end
 *
 * For IRQ44 it is observe-only and just prints begin/end so we can verify
 * that it stays pending until secure IRQ45 finishes.
 */

#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <asm-generic/irq_regs.h>

#define IRQGEN_REG_TRIGGER 0x0

struct nanhu_irq_preempt {
	void __iomem *ns_base;
	void __iomem *sec_base;
	unsigned int irq_count;
	int irq;
	bool auto_secure_trigger;
};

struct nanhu_irq_regs_snapshot {
	unsigned long epc;
	unsigned long status;
	unsigned long badaddr;
	unsigned long cause;
	unsigned long ra;
	unsigned long sp;
	unsigned long t0;
	unsigned long t1;
	unsigned long t2;
	unsigned long a0;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
	unsigned long a4;
	unsigned long a5;
	unsigned long a6;
	unsigned long a7;
	unsigned long s0;
	unsigned long s1;
	unsigned long s2;
	unsigned long s3;
	unsigned long s4;
	unsigned long s5;
	unsigned long s6;
	unsigned long s7;
	unsigned long s8;
	unsigned long s9;
	unsigned long s10;
	unsigned long s11;
	unsigned long t3;
	unsigned long t4;
	unsigned long t5;
	unsigned long t6;
};

static void nanhu_irq_snapshot(struct nanhu_irq_regs_snapshot *snap,
			       const struct pt_regs *regs)
{
	if (!regs || !snap)
		return;

	snap->epc = regs->epc;
	snap->status = regs->status;
	snap->badaddr = regs->badaddr;
	snap->cause = regs->cause;
	snap->ra = regs->ra;
	snap->sp = regs->sp;
	snap->t0 = regs->t0;
	snap->t1 = regs->t1;
	snap->t2 = regs->t2;
	snap->a0 = regs->a0;
	snap->a1 = regs->a1;
	snap->a2 = regs->a2;
	snap->a3 = regs->a3;
	snap->a4 = regs->a4;
	snap->a5 = regs->a5;
	snap->a6 = regs->a6;
	snap->a7 = regs->a7;
	snap->s0 = regs->s0;
	snap->s1 = regs->s1;
	snap->s2 = regs->s2;
	snap->s3 = regs->s3;
	snap->s4 = regs->s4;
	snap->s5 = regs->s5;
	snap->s6 = regs->s6;
	snap->s7 = regs->s7;
	snap->s8 = regs->s8;
	snap->s9 = regs->s9;
	snap->s10 = regs->s10;
	snap->s11 = regs->s11;
	snap->t3 = regs->t3;
	snap->t4 = regs->t4;
	snap->t5 = regs->t5;
	snap->t6 = regs->t6;
}

static bool nanhu_irq_snapshot_equal(const struct nanhu_irq_regs_snapshot *a,
				     const struct nanhu_irq_regs_snapshot *b)
{
	return a->epc == b->epc && a->status == b->status &&
	       a->badaddr == b->badaddr && a->cause == b->cause &&
	       a->ra == b->ra && a->sp == b->sp &&
	       a->t0 == b->t0 && a->t1 == b->t1 && a->t2 == b->t2 &&
	       a->a0 == b->a0 && a->a1 == b->a1 &&
	       a->a2 == b->a2 && a->a3 == b->a3 &&
	       a->a4 == b->a4 && a->a5 == b->a5 &&
	       a->a6 == b->a6 && a->a7 == b->a7 &&
	       a->s0 == b->s0 && a->s1 == b->s1 &&
	       a->s2 == b->s2 && a->s3 == b->s3 &&
	       a->s4 == b->s4 && a->s5 == b->s5 &&
	       a->s6 == b->s6 && a->s7 == b->s7 &&
	       a->s8 == b->s8 && a->s9 == b->s9 &&
	       a->s10 == b->s10 && a->s11 == b->s11 &&
	       a->t3 == b->t3 && a->t4 == b->t4 &&
	       a->t5 == b->t5 && a->t6 == b->t6;
}

static void nanhu_irq_trace_regs(const char *tag, int irq,
				 const struct pt_regs *regs)
{
	if (!regs) {
		pr_info("[REE-IRQ] %s irq=%d regs=NULL\n", tag, irq);
		return;
	}

	pr_info("[REE-IRQ] %s irq=%d epc=0x%lx status=0x%lx cause=0x%lx badaddr=0x%lx\n",
		tag, irq, regs->epc, regs->status, regs->cause,
		regs->badaddr);
	pr_info("[REE-IRQ] GPR irq=%d ra=0x%lx sp=0x%lx gp=0x%lx tp=0x%lx a0=0x%lx a1=0x%lx a2=0x%lx a3=0x%lx a4=0x%lx a5=0x%lx a6=0x%lx a7=0x%lx\n",
		irq, regs->ra, regs->sp, regs->gp, regs->tp,
		regs->a0, regs->a1, regs->a2, regs->a3,
		regs->a4, regs->a5, regs->a6, regs->a7);
	pr_info("[REE-IRQ] GPR irq=%d s0=0x%lx s1=0x%lx s2=0x%lx s3=0x%lx s4=0x%lx s5=0x%lx s6=0x%lx s7=0x%lx s8=0x%lx s9=0x%lx s10=0x%lx s11=0x%lx\n",
		irq, regs->s0, regs->s1, regs->s2, regs->s3, regs->s4,
		regs->s5, regs->s6, regs->s7, regs->s8, regs->s9,
		regs->s10, regs->s11);
	pr_info("[REE-IRQ] GPR irq=%d t0=0x%lx t1=0x%lx t2=0x%lx t3=0x%lx t4=0x%lx t5=0x%lx t6=0x%lx\n",
		irq, regs->t0, regs->t1, regs->t2, regs->t3,
		regs->t4, regs->t5, regs->t6);
}

static irqreturn_t nanhu_irq_handler(int irq, void *dev_id)
{
	struct nanhu_irq_preempt *priv = dev_id;
	struct nanhu_irq_regs_snapshot entry = { };
	struct nanhu_irq_regs_snapshot exit = { };
	struct pt_regs *regs = get_irq_regs();
	unsigned int count;

	nanhu_irq_snapshot(&entry, regs);
	nanhu_irq_trace_regs("SAVE", priv->irq, regs);

	count = ++priv->irq_count;
	if (priv->auto_secure_trigger)
		pr_info("[ree] irq%d begin count=%u: trigger secure peer\n",
			priv->irq, count);
	else
		pr_info("[ree] irq%d begin count=%u\n", priv->irq, count);

	if (priv->auto_secure_trigger) {
		/*
		 * Trigger the secure peer while we are still in the NS hardirq
		 * context.
		 *
		 * Use a raw MMIO store here to keep the test focused on
		 * interrupt preemption itself. The generic writel() path also
		 * updates Linux's per-CPU MMIO write-barrier bookkeeping,
		 * which is useful in general but makes it harder to
		 * distinguish an OpenSBI/TEE context-restore bug from a plain
		 * preemption result during bring-up.
		 */
		__raw_writel(1, priv->sec_base + IRQGEN_REG_TRIGGER);
	}

	pr_info("[ree] irq%d end count=%u\n", priv->irq, count);
	nanhu_irq_snapshot(&exit, regs);
	pr_info("[REE-IRQ] RESTORE-CHECK irq=%d result=%s epc=0x%lx status=0x%lx cause=0x%lx\n",
		priv->irq, nanhu_irq_snapshot_equal(&entry, &exit) ? "OK" : "CHANGED",
		regs ? regs->epc : 0, regs ? regs->status : 0,
		regs ? regs->cause : 0);
	return IRQ_HANDLED;
}

static int nanhu_irq_preempt_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *sec_np;
	struct resource sec_res;
	struct nanhu_irq_preempt *priv;
	int ret;

	if (!device_property_present(dev, "bosc,ree-preempt-test"))
		return -ENODEV;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->ns_base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(priv->ns_base))
		return PTR_ERR(priv->ns_base);

	sec_np = of_parse_phandle(dev_of_node(dev), "bosc,secure-trigger", 0);
	if (sec_np) {
		ret = of_address_to_resource(sec_np, 0, &sec_res);
		of_node_put(sec_np);
		if (ret)
			return dev_err_probe(dev, ret,
					     "failed to resolve secure trigger resource\n");

		priv->sec_base = devm_ioremap_resource(dev, &sec_res);
		if (IS_ERR(priv->sec_base))
			return PTR_ERR(priv->sec_base);

		priv->auto_secure_trigger = true;
	}

	priv->irq = platform_get_irq(pdev, 0);
	if (priv->irq < 0)
		return priv->irq;

	ret = devm_request_irq(dev, priv->irq, nanhu_irq_handler, 0,
			       dev_name(dev), priv);
	if (ret)
		return dev_err_probe(dev, ret, "failed to request test IRQ\n");

	platform_set_drvdata(pdev, priv);

	if (priv->auto_secure_trigger) {
		dev_info(dev,
			 "REE preemption test armed on IRQ%d, secure trigger at %pa\n",
			 priv->irq, &sec_res.start);
		dev_info(dev,
			 "Trigger NS%d and expect: [ree] irq%d begin -> secure peer path -> [ree] irq%d end\n",
			 priv->irq, priv->irq, priv->irq);
	} else {
		dev_info(dev, "REE observe-only test armed on IRQ%d\n",
			 priv->irq);
		dev_info(dev,
			 "Trigger NS%d and expect only [ree] irq%d begin/end after secure peer completes\n",
			 priv->irq, priv->irq);
	}

	return 0;
}

static const struct of_device_id nanhu_irq_preempt_of_match[] = {
	{ .compatible = "bosc,nanhu-irqgen" },
	{ }
};
MODULE_DEVICE_TABLE(of, nanhu_irq_preempt_of_match);

static struct platform_driver nanhu_irq_preempt_driver = {
	.probe = nanhu_irq_preempt_probe,
	.driver = {
		.name = "nanhu-irq-preempt-test",
		.of_match_table = nanhu_irq_preempt_of_match,
	},
};
module_platform_driver(nanhu_irq_preempt_driver);

MODULE_DESCRIPTION("BOSC Nanhu REE/TEE IRQ preemption test driver");
MODULE_AUTHOR("Marigold");
MODULE_LICENSE("GPL");
