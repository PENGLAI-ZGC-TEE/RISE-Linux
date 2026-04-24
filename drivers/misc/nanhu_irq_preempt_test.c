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

#define IRQGEN_REG_TRIGGER 0x0

struct nanhu_irq_preempt {
	void __iomem *ns_base;
	void __iomem *sec_base;
	unsigned int irq_count;
	int irq;
	bool auto_secure_trigger;
};

static irqreturn_t nanhu_irq_handler(int irq, void *dev_id)
{
	struct nanhu_irq_preempt *priv = dev_id;
	unsigned int count;

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
