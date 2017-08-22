/* Copyright (c) 2014, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <linux/err.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/watchdog.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/sched.h>
#include <mach/scm.h>

#define WDT_RST		0x0
#define WDT_EN		0x8
#define WDT_BARK_TIME	0x14
#define WDT_BITE_TIME	0x24

struct qcom_wdt {
	struct watchdog_device	wdd;
	struct device		*dev;
	unsigned long		rate;
	void __iomem		*base;
	unsigned int		irq;
	void 			**percpu;
	void			*scm_regsave;
};

static inline
struct qcom_wdt *to_qcom_wdt(struct watchdog_device *wdd)
{
	return container_of(wdd, struct qcom_wdt, wdd);
}

static void qcom_wdt_scm_regsave(void *info)
{
	struct qcom_wdt *wdt = (struct qcom_wdt *)info;
    int ret;
	struct {
		unsigned addr;
		int len;
	} cmd_buf;

	if (!wdt->scm_regsave)
		return;

	cmd_buf.addr = __pa(wdt->scm_regsave);
	cmd_buf.len  = PAGE_SIZE;

#define SCM_SET_REGSAVE_CMD 0x2
	ret = scm_call(SCM_SVC_UTIL, SCM_SET_REGSAVE_CMD,
		       &cmd_buf, sizeof(cmd_buf), NULL, 0);
	if (ret) {
		dev_err(wdt->dev, "Setting register save address failed");
	}
}

static int qcom_wdt_start(struct watchdog_device *wdd)
{
	struct qcom_wdt *wdt = to_qcom_wdt(wdd);

	writel(0, wdt->base + WDT_EN);

	smp_call_function_single(0, qcom_wdt_scm_regsave, (void *)wdt, true);

	writel(wdd->timeout * wdt->rate / 2, wdt->base + WDT_BARK_TIME);
	writel(wdd->timeout * wdt->rate, wdt->base + WDT_BITE_TIME);

	writel(1, wdt->base + WDT_EN);
	writel(1, wdt->base + WDT_RST);

	enable_percpu_irq(wdt->irq, IRQ_TYPE_EDGE_RISING);

	return 0;
}

static int qcom_wdt_stop(struct watchdog_device *wdd)
{
	struct qcom_wdt *wdt = to_qcom_wdt(wdd);

	writel(0, wdt->base + WDT_EN);
	disable_percpu_irq(wdt->irq);
	return 0;
}

static int qcom_wdt_ping(struct watchdog_device *wdd)
{
	struct qcom_wdt *wdt = to_qcom_wdt(wdd);

	writel(1, wdt->base + WDT_RST);
	return 0;
}

static int qcom_wdt_set_timeout(struct watchdog_device *wdd,
				unsigned int timeout)
{
	wdd->timeout = timeout;
	return qcom_wdt_start(wdd);
}

static irqreturn_t qcom_wdt_bark_handler(int irq, void *dev_id)
{
	unsigned long long t = sched_clock();
	unsigned long nsec_rem = do_div(t, 1000000000);
	struct task_struct *tsk;

	pr_emerg("qcom_wdt bark! %lu.%06lu\n", (unsigned long) t,
		nsec_rem / 1000);

	for_each_process(tsk) {
		pr_info("\nPID: %d, Name: %s\n",
			tsk->pid, tsk->comm);
		show_stack(tsk, NULL);
	}

	/* cjf: show all cpu stack. */
	smp_send_all_cpu_backtrace();

	return IRQ_HANDLED;
}

static const struct watchdog_ops qcom_wdt_ops = {
	.start		= qcom_wdt_start,
	.stop		= qcom_wdt_stop,
	.ping		= qcom_wdt_ping,
	.set_timeout	= qcom_wdt_set_timeout,
	.owner		= THIS_MODULE,
};

static const struct watchdog_info qcom_wdt_info = {
	.options	= WDIOF_KEEPALIVEPING
			| WDIOF_MAGICCLOSE
			| WDIOF_SETTIMEOUT,
	.identity	= KBUILD_MODNAME,
};

static int qcom_wdt_probe(struct platform_device *pdev)
{
	struct qcom_wdt *wdt;
	struct resource *res;
	int ret;

	wdt = devm_kzalloc(&pdev->dev, sizeof(*wdt), GFP_KERNEL);
	if (!wdt)
		return -ENOMEM;

	platform_set_drvdata(pdev, wdt);
	wdt->dev = &pdev->dev;
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	wdt->base = devm_ioremap(&pdev->dev, res->start, resource_size(res));
	if (IS_ERR(wdt->base))
		return PTR_ERR(wdt->base);

	/* Bypass COMMON_CLK and hardcode rate */
	wdt->rate = 32768;
	if (wdt->rate == 0 ||
	    wdt->rate > 0x10000000U) {
		dev_err(&pdev->dev, "invalid clock rate\n");
		return -EINVAL;
	}

	wdt->wdd.info = &qcom_wdt_info;
	wdt->wdd.ops = &qcom_wdt_ops;
	wdt->wdd.min_timeout = 1;
	wdt->wdd.max_timeout = 0x10000000U / wdt->rate;
	wdt->irq = platform_get_irq(pdev, 0);
	wdt->scm_regsave = (void *)__get_free_page(GFP_KERNEL);

	if (!wdt->scm_regsave) {
		dev_warn(&pdev->dev, "Allocating register save space failed\n");
	}

	/*
	 * If 'timeout-sec' unspecified in devicetree, assume a 30 second
	 * default, unless the max timeout is less than 30 seconds, then use
	 * the max instead.
	 */
	wdt->wdd.timeout = min(wdt->wdd.max_timeout, 30U);

	ret = watchdog_register_device(&wdt->wdd);
	if (ret) {
		dev_err(&pdev->dev, "failed to register watchdog\n");
		return ret;
	}

	if (!wdt->irq) {
		goto irq_failed;
	}

	wdt->percpu = alloc_percpu(void *);
	if (!wdt->percpu) {
		dev_warn(&pdev->dev, "alloc_percpu failed, no watchdog irq\n");
		goto irq_failed;
	}

	ret = request_percpu_irq(wdt->irq, qcom_wdt_bark_handler,
				"qcom_wdt_bark_handler", wdt->percpu);
	if (ret) {
		dev_warn(&pdev->dev,
			"unable to register watchdog bark interrupt\n");
		free_percpu(wdt->percpu);
		goto irq_failed;
	}

irq_failed:
	return 0;
}

static int qcom_wdt_remove(struct platform_device *pdev)
{
	struct qcom_wdt *wdt = platform_get_drvdata(pdev);

	if (wdt->scm_regsave)
		__free_page(wdt->scm_regsave);
	free_percpu_irq(wdt->irq, 0);
	free_percpu(wdt->percpu);
	watchdog_unregister_device(&wdt->wdd);
	return 0;
}

static const struct of_device_id qcom_wdt_of_table[] = {
	{ .compatible = "qcom,kpss-wdt-msm8960", },
	{ .compatible = "qcom,kpss-wdt-apq8064", },
	{ .compatible = "qcom,kpss-wdt-ipq8064", },
	{ },
};
MODULE_DEVICE_TABLE(of, qcom_wdt_of_table);

static struct platform_driver qcom_watchdog_driver = {
	.probe	= qcom_wdt_probe,
	.remove	= qcom_wdt_remove,
	.driver	= {
		.name		= KBUILD_MODNAME,
		.of_match_table	= qcom_wdt_of_table,
	},
};
module_platform_driver(qcom_watchdog_driver);

MODULE_DESCRIPTION("QCOM KPSS Watchdog Driver");
MODULE_LICENSE("GPL v2");
